//! The send strategy in the connection's tree: its core in the connection
//! node, a send planner in the node of each link path, and what each is
//! told when the components it follows change.
//!
//! Whoever changes a key, the handshake's confirmation, the record of why
//! the connection closed or a link path's role only changes its own
//! component; the core and the planners read those components, and the
//! driver rereads them after a lend that changed one. Each remembers what
//! it told the strategy last, so the same fact is told once.

use core::fmt;

use sakuya_link::Link;
use sakuya_packet_protection::{backend::AEAD_TAG_LEN, packet_number::TruncatedPacketNumber};
use sakuya_wire::{
    header::SAMPLE_DISTANCE,
    parameters::ParametersOf,
    parts::Selector,
    v1::{
        encryption_level::EncryptionLevel,
        packet_number::PacketNumber,
        role::Role,
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace, integer::MaxUdpPayloadSize,
        },
    },
    var_int::{VarInt, VarIntWidth},
};

use sakuya_recovery::{
    ack_obligation::{AckDue, AckObligation},
    congestion::CongestionController,
    pacing::Pacer,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pmtu::PmtuPolicy,
    receive_journals::ReceiveJournals,
    send_journals::SendJournals,
};

use super::{
    AckObligationsOf, Choices, CloseCauseOf, Side,
    amplification::AntiAmplification,
    close::CloseReasonRecord,
    confirmation::HandshakeConfirmation,
    connection_ids::{ConnectionIdsOf, ResetTokenRegistrarOf},
    keys::{HandshakeKeys, InitialKeys, OneRttKeys},
    link::{FirstLinkStart, LinkClone, LinkFacts},
    parameters::PeerTransportParameters,
    recovery::{CongestionPartOf, LinkPathCongestionState, PmtuOf, peer_max_udp_payload_size},
    role::LinkPathRole,
    send::{AckIntent, ProbePingIntent, SendTypes, shortest_ack_frame},
    spaces::SendJournalsOf,
};
use crate::{
    call::CallBundle,
    clock::{InstantOf, LinkIdOf},
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, ReadSet,
        RequestOf,
    },
    connection_id::DestinationConnectionIdStrategy,
    feedback::FeedbackSummariesOf,
    layer::{self, NodeKey},
    others::OtherNodes,
    send_strategy::{
        AnyActiveLinkPath, DatagramLimits, LinkPathRoleKind, LinkPathSendPlanner, Observe,
        PacketOverheads, PlannerLinkPath, Publish, PublishOutcome, PublishTo, SendStrategy,
        SendStrategyTypes,
    },
    share::{FlatRef, LineageLists, LineagePartList, LogicalPathKeys, NodeData},
    take::{GetAt, ReadEach, Take, TakeEach},
    write::FlightClass,
};

/// The core of the send strategy of the choices `T` and the list of parts
/// `L`.
pub type SendStrategyOf<T, L> = <T as Choices>::SendStrategy<SendTypes<T, L>>;

/// The send planner of one link path, as the core of `T` and `L` makes it.
pub type LinkPathSendPlannerOf<T, L> =
    <SendStrategyOf<T, L> as SendStrategy<SendTypes<T, L>>>::LinkPathSendPlanner;

// ---- the core ----

/// The connection's events the core has been told.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ToldEvents {
    initial_keys: bool,
    handshake_keys: bool,
    one_rtt_keys: bool,
    confirmed: bool,
    closed: bool,
}

/// The core of a send strategy, in the connection node, with the
/// connection's events it has been told.
pub struct SendStrategyCore<S> {
    strategy: S,
    told: ToldEvents,
}

impl<S> fmt::Debug for SendStrategyCore<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendStrategyCore")
            .field("told", &self.told)
            .finish_non_exhaustive()
    }
}

impl<S> SendStrategyCore<S> {
    /// The core `strategy`, told nothing yet.
    pub fn new(strategy: S) -> Self {
        Self {
            strategy,
            told: ToldEvents::default(),
        }
    }

    /// The core.
    pub fn strategy(&self) -> &S {
        &self.strategy
    }

    /// The core, to publish to or to plan with.
    pub fn strategy_mut(&mut self) -> &mut S {
        &mut self.strategy
    }
}

/// The core starts as the choices' strategy makes it by default.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for SendStrategyCore<SendStrategyOf<T, L>>
where
    L: LineagePartList<T>,
    SendTypes<T, L>: SendStrategyTypes,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Self::new(SendStrategyOf::<T, L>::default())
    }
}

/// The core is told when the keys to send at a level are first in place,
/// when the handshake is confirmed, and, in the poll the reason is
/// recorded, that no link path will be active again.
impl<T: Choices, L, I, Ii, Ih, Io, If, Ic>
    DataComponent<T, L, layer::Connection, (I, Ii, Ih, Io, If, Ic)>
    for SendStrategyCore<SendStrategyOf<T, L>>
where
    L: LineagePartList<T> + LogicalPathKeys + crate::error::ConnectionErrorsOf,
    SendTypes<T, L>: SendStrategyTypes<CloseCause = CloseCauseOf<T, L>>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<Self, I>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<HandshakeConfirmation, If>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
{
    fn reads(reads: &mut ReadSet) {
        reads
            .add::<InitialKeys<T::Crypto>>()
            .add::<HandshakeKeys<T::Crypto>>()
            .add::<OneRttKeys<T::Crypto, InstantOf<T>>>()
            .add::<HandshakeConfirmation>()
            .add::<CloseReasonRecord<CloseCauseOf<T, L>>>();
    }

    fn reread<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let told = lineage.get::<Self, I>().told;
        let now = ToldEvents {
            initial_keys: told.initial_keys
                || lineage.get::<InitialKeys<T::Crypto>, Ii>().send().is_some(),
            handshake_keys: told.handshake_keys
                || lineage
                    .get::<HandshakeKeys<T::Crypto>, Ih>()
                    .send()
                    .is_some(),
            one_rtt_keys: told.one_rtt_keys
                || lineage
                    .get::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>()
                    .send()
                    .is_some(),
            confirmed: told.confirmed
                || *lineage.get::<HandshakeConfirmation, If>() == HandshakeConfirmation::Confirmed,
            closed: told.closed
                || lineage
                    .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                    .is_written(),
        };
        if now == told {
            return None;
        }
        let reason = (now.closed && !told.closed).then(|| {
            lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .reason()
                .cloned()
        });
        let core = lineage.get_mut::<Self, I>();
        core.told = now;
        let strategy = &mut core.strategy;
        for (was, is, level) in [
            (
                told.initial_keys,
                now.initial_keys,
                EncryptionLevel::Initial,
            ),
            (
                told.handshake_keys,
                now.handshake_keys,
                EncryptionLevel::Handshake,
            ),
            (told.one_rtt_keys, now.one_rtt_keys, EncryptionLevel::OneRtt),
        ] {
            if is && !was {
                strategy.send_keys_available(level);
            }
        }
        if now.confirmed && !told.confirmed {
            strategy.handshake_confirmed();
        }
        if let Some(Some(reason)) = reason {
            strategy.no_more_active_link_paths(reason);
        }
        None
    }
}

// ---- the planners ----

/// The send planner of a link path, in the link path's node, with the
/// role, the limits and the packet overheads it was last told.
pub struct LinkPathPlanner<P> {
    planner: P,
    role: LinkPathRoleKind,
    limits: Option<DatagramLimits>,
    overheads: Option<PacketOverheads>,
}

impl<P> fmt::Debug for LinkPathPlanner<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkPathPlanner")
            .field("role", &self.role)
            .field("limits", &self.limits)
            .field("overheads", &self.overheads)
            .finish_non_exhaustive()
    }
}

impl<P> LinkPathPlanner<P> {
    /// The planner.
    pub fn planner(&self) -> &P {
        &self.planner
    }

    /// Tell the planner what the link path can send in its next new
    /// datagram and what each kind of packet takes beyond its frames, as
    /// they are now.
    pub(super) fn observe_conditions(&mut self, limits: DatagramLimits, overheads: PacketOverheads)
    where
        P: Observe<DatagramLimits> + Observe<PacketOverheads>,
    {
        self.limits = Some(limits);
        self.overheads = Some(overheads);
        self.planner.observe(limits);
        self.planner.observe(overheads);
    }

    /// The planner, to publish to, to tell of its send conditions or to
    /// plan with.
    pub fn planner_mut(&mut self) -> &mut P {
        &mut self.planner
    }
}

/// The role a link path starts in, as its role component decides it: the
/// connection's first link path is active from the start, a later one is
/// a candidate.
fn starting_role(first: &FirstLinkStart) -> LinkPathRoleKind {
    if first.path_pending() {
        LinkPathRoleKind::Active
    } else {
        LinkPathRoleKind::Candidate
    }
}

/// A link path's planner is made by the core when the link path is built,
/// in the role the link path starts in, and handed back to the core when
/// the link path ends. It is built before the link path's role, which
/// takes the mark of the first link path.
impl<T: Choices, L, Ic, If> Build<T, L, layer::LinkPath, (Ic, If)>
    for LinkPathPlanner<LinkPathSendPlannerOf<T, L>>
where
    L: LineagePartList<T> + LogicalPathKeys,
    SendTypes<T, L>:
        SendStrategyTypes<LinkPathIdentifier = crate::share::LinkPathIdentifierOf<T, L>>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    for<'v> <L as LineageLists<'v, T>>::LinkPathParents:
        GetAt<SendStrategyCore<SendStrategyOf<T, L>>, Ic> + GetAt<FirstLinkStart, If>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        args: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        let role = starting_role(parents.get::<FirstLinkStart, If>());
        let identifier = L::link_path_identifier(&args.path, &args.link);
        let planner = parents
            .get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Ic>()
            .strategy_mut()
            .add_link_path(identifier, role);
        Self {
            planner,
            role,
            limits: None,
            overheads: None,
        }
    }

    fn end<'v, B: CallBundle>(
        self,
        parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        _: &mut OtherNodes<'v, T, L, B>,
    ) {
        self.planner.ended(
            parents
                .get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Ic>()
                .strategy_mut(),
        );
    }
}

/// A planner is told when its link path's role changes; what the link
/// path can send whenever a component that limits it changes: the
/// anti-amplification credit, the peer's transport parameters, and the
/// congestion control, its fixed state and the datagram size probing
/// policy in the link path's recovery layer; and what each kind of packet
/// takes beyond its frames whenever a component it follows from changes:
/// the connection IDs, the packet number states and send journals of the
/// spaces, and the keys of each level. All of it is only read here.
impl<T: Choices, L, Ip, Ir, It, Il, Io, Ipp, Jc, Js, Jm>
    DataComponent<T, L, layer::LinkPath, (Ip, Ir, It, Il, Io, Ipp, (Jc, Js, Jm))>
    for LinkPathPlanner<LinkPathSendPlannerOf<T, L>>
where
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    LinkPathSendPlannerOf<T, L>: Observe<DatagramLimits> + Observe<PacketOverheads>,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, Ipp>,
    CongestionPartOf<T, L>: CongestionController<InstantOf<T>> + Pacer<InstantOf<T>>,
    for<'v> <L as LineageLists<'v, T>>::LinkPath: GetAt<Self, Ip>
        + GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + ReadEach<DatagramLimitsReads<T, L>, Il>
        + ReadEach<PacketOverheadsReads<T, L>, Io>
        + TakeEach<'v, frunk_core::HList![Self, SendStrategyCore<SendStrategyOf<T, L>>], It>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jc>
        + Selector<&'a LinkPathCongestionState<InstantOf<T>>, Js>
        + Selector<&'a PmtuOf<T, L>, Jm>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add::<LinkPathRole<InstantOf<T>>>();
        reads.add::<AntiAmplification>();
        reads.add::<PeerTransportParameters<TransportParameterSlots<L>>>();
        reads.add::<CongestionPartOf<T, L>>();
        reads.add::<LinkPathCongestionState<InstantOf<T>>>();
        reads.add::<PmtuOf<T, L>>();
        reads.add::<ConnectionIdsOf<T>>();
        reads.add::<PacketNumberSpaces<PacketNumberSpaceState>>();
        reads.add::<SendJournalsOf<T, L>>();
        reads.add::<InitialKeys<T::Crypto>>();
        reads.add::<HandshakeKeys<T::Crypto>>();
        reads.add::<OneRttKeys<T::Crypto, InstantOf<T>>>();
    }

    fn reread<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let NodeKey::LinkPath(_, link) = others.here() else {
            unreachable!("a link path's lend carries its key")
        };
        let role = lineage.get::<LinkPathRole<InstantOf<T>>, Ir>().kind();
        let limits = read_datagram_limits::<T, L, B, Il, Ipp, Jc, Js, Jm>(&lineage, others);
        let overheads = read_packet_overheads::<T, L, Io>(
            &lineage,
            link,
            limits.capacity_for(FlightClass::AckOnly),
        );
        let told = lineage.get::<Self, Ip>();
        if told.role == role && told.limits == Some(limits) && told.overheads == Some(overheads) {
            return None;
        }
        let (frunk_core::hlist_pat![planner, core], _) = Take::<
            frunk_core::HList![Self, SendStrategyCore<SendStrategyOf<T, L>>],
            It,
        >::take(lineage);
        if planner.role != role {
            planner.role = role;
            planner.planner.role_changed(core.strategy_mut(), role);
        }
        if planner.limits != Some(limits) {
            planner.limits = Some(limits);
            planner.planner.observe(limits);
        }
        if planner.overheads != Some(overheads) {
            planner.overheads = Some(overheads);
            planner.planner.observe(overheads);
        }
        None
    }
}

// ---- what a link path can send ----

/// What a link path's recovery layer says about what it can send: what the
/// congestion window leaves, what pacing releases and how many datagrams
/// may go past both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CongestionAllowance {
    pub(super) window_left: usize,
    pub(super) pacing_allowance: usize,
    pub(super) probe_permits: u8,
}

/// The peer's `max_udp_payload_size` when it left it out (RFC 9000 §18.2),
/// taken too while its transport parameters are not known.
const DEFAULT_PEER_MAX_UDP_PAYLOAD: usize = 65527;

/// What a link path can send in its next new datagram, from the raw
/// quantities of its components: the link's ceiling (`None` when asking
/// failed), the peer's `max_udp_payload_size` (`None` while its transport
/// parameters are not known), what path MTU discovery concluded and what
/// congestion control allows (`None` without a recovery layer), and the
/// anti-amplification credit.
///
/// A link path without a recovery layer has no congestion window: it
/// sends nothing that counts in flight, and its datagrams are of the
/// least size every path supports (RFC 9000 §14).
pub(super) fn datagram_limits(
    link_ceiling: Option<usize>,
    peer_max_udp_payload: Option<usize>,
    anti_amplification_credit: Option<u64>,
    recovery: Option<(usize, CongestionAllowance)>,
) -> DatagramLimits {
    let (pmtu_conclusion, congestion) = recovery.unwrap_or((
        DatagramLimits::MINIMUM,
        CongestionAllowance {
            window_left: 0,
            pacing_allowance: 0,
            probe_permits: 0,
        },
    ));
    DatagramLimits {
        link_ceiling,
        peer_max_udp_payload: peer_max_udp_payload.unwrap_or(DEFAULT_PEER_MAX_UDP_PAYLOAD),
        pmtu_conclusion,
        anti_amplification_credit,
        congestion_window_left: congestion.window_left,
        pacing_allowance: congestion.pacing_allowance,
        probe_permits: congestion.probe_permits,
    }
}

/// What a link path's planner reads from the nodes above it to tell its
/// strategy what the link path can send: the logical link, its facts and
/// anti-amplification state, and the peer's transport parameters.
pub(super) type DatagramLimitsReads<T, L> = frunk_core::HList![
    LinkClone<<T as crate::clock::ConnectionChoices>::Link>,
    LinkFacts,
    AntiAmplification,
    PeerTransportParameters<TransportParameterSlots<L>>,
];

/// What a link path can send in its next new datagram, read from the link
/// path's lend without taking anything: the pacer is not refilled, so its
/// allowance is what its last refill left.
fn read_datagram_limits<'v, T, L, B, Il, Ipp, Jc, Js, Jm>(
    lineage: &LineageOf<'v, T, L, layer::LinkPath>,
    others: &OtherNodes<'v, T, L, B>,
) -> DatagramLimits
where
    T: Choices,
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace>,
    B: CallBundle,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, Ipp>,
    CongestionPartOf<T, L>: CongestionController<InstantOf<T>> + Pacer<InstantOf<T>>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: ReadEach<DatagramLimitsReads<T, L>, Il>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jc>
        + Selector<&'a LinkPathCongestionState<InstantOf<T>>, Js>
        + Selector<&'a PmtuOf<T, L>, Jm>,
{
    let frunk_core::hlist_pat![link, facts, amplification, peer] =
        lineage.read_each::<DatagramLimitsReads<T, L>, Il>();
    let recovery = others.recovery_ref().map(|flat| {
        let controller: &&CongestionPartOf<T, L> = Selector::<_, Jc>::get(&flat);
        let state: &&LinkPathCongestionState<InstantOf<T>> = Selector::<_, Js>::get(&flat);
        let pmtu: &&PmtuOf<T, L> = Selector::<_, Jm>::get(&flat);
        (
            pmtu.conclusion(),
            CongestionAllowance {
                window_left: state.window_left(*controller),
                pacing_allowance: Pacer::allowance(*controller),
                probe_permits: state.probe_permits(),
            },
        )
    });
    datagram_limits(
        link.0.max_datagram_size().ok(),
        peer_max_udp_payload_size::<L, Ipp>(peer),
        amplification.credit(facts.validation),
        recovery,
    )
}

// ---- what a packet takes beyond its frames ----

/// What a link path's planner reads from the nodes above it to tell its
/// strategy what each kind of packet takes beyond its frames: the
/// connection IDs, the packet number states and the send journals of the
/// spaces, and the keys of each level.
pub(super) type PacketOverheadsReads<T, L> = frunk_core::HList![
    ConnectionIdsOf<T>,
    PacketNumberSpaces<PacketNumberSpaceState>,
    SendJournalsOf<T, L>,
    InitialKeys<<T as Choices>::Crypto>,
    HandshakeKeys<<T as Choices>::Crypto>,
    OneRttKeys<<T as Choices>::Crypto, InstantOf<T>>,
];

/// Which levels have keys to send packets with now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SendKeyLevels {
    pub(super) initial: bool,
    pub(super) handshake: bool,
    pub(super) one_rtt: bool,
}

/// What each kind of packet takes beyond its frames on the link path over
/// `link` now, and the length of the shortest connection ID offered for
/// it, `None` when none is: from the destination connection IDs offered
/// for the link path and this side's connection ID in `ids`, the next
/// packet numbers of the spaces whose levels have keys in `keys`, as
/// `journals` and `numbers` give them, and `max_len`, the largest datagram
/// the link path can send now.
pub(super) fn link_path_packet_overheads<T, L>(
    ids: &ConnectionIdsOf<T>,
    link: &LinkIdOf<T>,
    numbers: &PacketNumberSpaces<PacketNumberSpaceState>,
    journals: &SendJournalsOf<T, L>,
    keys: SendKeyLevels,
    max_len: usize,
) -> (Option<usize>, PacketOverheads)
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf,
{
    let shortest = DestinationConnectionIdStrategy::<
        LinkIdOf<T>,
        InstantOf<T>,
        ResetTokenRegistrarOf<T>,
    >::offer(ids.destination(), link)
    .map(|offered| offered.id.len())
    .min();
    let next = |space, keys: bool| {
        let journals = journals.get(space).filter(|_| keys)?;
        Some(NextPacketNumber {
            next: journals.next_packet_number(),
            largest_acked: numbers
                .get(space)
                .and_then(PacketNumberSpaceState::largest_acked),
        })
    };
    let overheads = packet_overheads(
        shortest,
        ids.local().len(),
        max_len,
        next(PacketNumberSpaceKind::Initial, keys.initial),
        next(PacketNumberSpaceKind::Handshake, keys.handshake),
        next(PacketNumberSpaceKind::ApplicationData, keys.one_rtt),
        <T::Side as Side>::ROLE,
    );
    (shortest, overheads)
}

/// What each kind of packet takes beyond its frames on the link path over
/// `link`, read from the link path's lend without taking anything, for
/// datagrams of at most `max_len` bytes.
fn read_packet_overheads<'v, T, L, Io>(
    lineage: &LineageOf<'v, T, L, layer::LinkPath>,
    link: &LinkIdOf<T>,
    max_len: usize,
) -> PacketOverheads
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: ReadEach<PacketOverheadsReads<T, L>, Io>,
{
    let frunk_core::hlist_pat![ids, numbers, journals, initial, handshake, one_rtt] =
        lineage.read_each::<PacketOverheadsReads<T, L>, Io>();
    let keys = SendKeyLevels {
        initial: initial.send().is_some(),
        handshake: handshake.send().is_some(),
        one_rtt: one_rtt.send().is_some(),
    };
    link_path_packet_overheads::<T, L>(ids, link, numbers, journals, keys, max_len).1
}

/// The bytes of the Version field of a long header (RFC 9000 §17.2).
const VERSION_LEN: usize = 4;

/// The packet number the next packet of a packet number space gets, and the
/// largest one acknowledged in that space: the length of its Packet Number
/// field follows from them (RFC 9000 §17.1, Appendix A.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NextPacketNumber {
    pub(super) next: PacketNumber,
    pub(super) largest_acked: Option<PacketNumber>,
}

impl NextPacketNumber {
    /// The length of the Packet Number field of the next packet, as the
    /// packet writer encodes it; `None` when four bytes cannot cover the
    /// packets not acknowledged.
    fn encoded_len(self) -> Option<usize> {
        let truncated = TruncatedPacketNumber::encode(self.next, self.largest_acked).ok()?;
        Some(truncated.encoded_len().get())
    }
}

/// What a packet of each kind takes beyond its frames on a link path now,
/// from the fixed parts of its header and its AEAD tag, and the PADDING its
/// header protection sample needs: the Packet Number field and the payload
/// take at least [`SAMPLE_DISTANCE`] bytes together (RFC 9001 §5.4.2), and
/// the packet writer gives no room to frames shorter than what the Packet
/// Number field leaves of them.
///
/// `dcid_len` is the length of the shortest connection ID offered for the
/// link path, `None` when none is; `scid_len` the length of this side's
/// connection ID a long header carries. `max_len` is the largest datagram
/// the link path can send now: the packet writer reserves a long header's
/// Length field wide enough for it. `initial`, `handshake` and `one_rtt`
/// are the next packet numbers of the spaces whose levels have keys to
/// send with, `None` for one that has none; a 0-RTT packet is never
/// planned, as no 0-RTT keys to send with are kept. An Initial packet's
/// token is empty: a server's always is (RFC 9000 §17.2.2), and a client
/// keeps none to send.
pub(super) fn packet_overheads(
    dcid_len: Option<usize>,
    scid_len: usize,
    max_len: usize,
    initial: Option<NextPacketNumber>,
    handshake: Option<NextPacketNumber>,
    one_rtt: Option<NextPacketNumber>,
    role: Role,
) -> PacketOverheads {
    let length_width =
        VarIntWidth::shortest(VarInt::try_from(max_len).unwrap_or(VarInt::MAX)).encoded_len();
    let empty_token = VarIntWidth::shortest(VarInt::ZERO).encoded_len();
    // the Packet Number field, and what the sample needs of the payload
    let numbered = |pn_len: usize| pn_len + SAMPLE_DISTANCE.saturating_sub(pn_len);
    let long = |dcid_len: usize, numbers: Option<NextPacketNumber>, token: usize| {
        let pn_len = numbers?.encoded_len()?;
        Some(
            1 + VERSION_LEN
                + 1
                + dcid_len
                + 1
                + scid_len
                + token
                + length_width
                + numbered(pn_len)
                + AEAD_TAG_LEN,
        )
    };
    let Some(dcid_len) = dcid_len else {
        return PacketOverheads {
            expands_every_initial: role == Role::Client,
            ..PacketOverheads::default()
        };
    };
    PacketOverheads {
        initial: long(dcid_len, initial, empty_token),
        handshake: long(dcid_len, handshake, 0),
        zero_rtt: None,
        one_rtt: one_rtt
            .and_then(NextPacketNumber::encoded_len)
            .map(|pn_len| 1 + dcid_len + numbered(pn_len) + AEAD_TAG_LEN),
        expands_every_initial: role == Role::Client,
    }
}

// ---- the ACK intents ----

/// What publishing an ACK intent for any active link path gives back in
/// the core of `T` and `L`.
pub type AckIntentTicketOf<T, L> = <SendStrategyOf<T, L> as PublishOutcome<
    AckIntent,
    <SendStrategyOf<T, L> as SendStrategy<SendTypes<T, L>>>::Destination,
>>::Outcome;

/// The ACK intents of a logical path: for each packet number space where
/// an ACK frame is due now, what publishing its intent gave back, with the
/// shortest frame the intent asked room for. Dropping an intent's ticket
/// withdraws it.
pub struct AckIntentTickets<K> {
    published: [Option<(K, usize)>; 3],
}

impl<K> fmt::Debug for AckIntentTickets<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shortest = self
            .published
            .each_ref()
            .map(|published| published.as_ref().map(|(_, shortest)| *shortest));
        f.debug_struct("AckIntentTickets")
            .field("shortest", &shortest)
            .finish_non_exhaustive()
    }
}

impl<K> Default for AckIntentTickets<K> {
    fn default() -> Self {
        Self {
            published: [None, None, None],
        }
    }
}

fn space_index(space: PacketNumberSpaceKind) -> usize {
    match space {
        PacketNumberSpaceKind::Initial => 0,
        PacketNumberSpaceKind::Handshake => 1,
        PacketNumberSpaceKind::ApplicationData => 2,
    }
}

impl<K> AckIntentTickets<K> {
    /// Whether an ACK intent of `space` is published.
    pub fn is_published(&self, space: PacketNumberSpaceKind) -> bool {
        self.published[space_index(space)].is_some()
    }

    /// Drop the ticket of `space`, whose intent an ACK frame consumed and
    /// that frame was lost: the intent is published again while an ACK
    /// frame is due.
    pub(crate) fn forget(&mut self, space: PacketNumberSpaceKind) {
        self.published[space_index(space)] = None;
    }
}

/// A logical path starts with no ACK frame due.
impl<T: Choices, L> Build<T, L, layer::LogicalPath, ()>
    for AckIntentTickets<AckIntentTicketOf<T, L>>
where
    L: LineagePartList<T>,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>
        + PublishOutcome<
            AckIntent,
            <SendStrategyOf<T, L> as SendStrategy<SendTypes<T, L>>>::Destination,
        >,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        Self::default()
    }
}

/// An ACK intent is published to the core for any active link path while
/// a space's ACK obligation says an ACK frame is due now, and withdrawn
/// when it no longer is or the space is gone. It asks room for the shortest
/// frame the space's receive journals give, and is published again when
/// that grows, so it is never planned for a packet its frame does not fit,
/// and when an ACK frame of the space is lost, which drops its ticket.
///
/// Not here: an ACK frame carried along when the obligation only wants one
/// in a packet sent anyway.
impl<T: Choices, L, Ia, Ij, Is, It, Idx>
    DataComponent<T, L, layer::LogicalPath, (Ia, Ij, Is, It, Idx)>
    for AckIntentTickets<AckIntentTicketOf<T, L>>
where
    L: LineagePartList<T>,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>
        + PublishTo<
            AckIntent,
            <SendStrategyOf<T, L> as SendStrategy<SendTypes<T, L>>>::Destination,
            Idx,
        >,
    <SendStrategyOf<T, L> as SendStrategy<SendTypes<T, L>>>::Destination: From<AnyActiveLinkPath>,
    for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<AckObligationsOf<T>, Ia>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<Self, Is>
        + TakeEach<'v, frunk_core::HList![Self, SendStrategyCore<SendStrategyOf<T, L>>], It>,
{
    fn reads(reads: &mut ReadSet) {
        reads
            .add::<AckObligationsOf<T>>()
            .add::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>>();
    }

    fn reread<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, layer::LogicalPath>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let wanted = PacketNumberSpaceKind::ALL.map(|space| {
            let due = lineage
                .get::<AckObligationsOf<T>, Ia>()
                .get(space)
                .is_some_and(|obligation| obligation.due() == AckDue::Now);
            due.then(|| {
                lineage
                    .get::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>()
                    .get(space)
                    .and_then(shortest_ack_frame)
            })
            .flatten()
        });
        let published = &lineage.get::<Self, Is>().published;
        let unchanged = wanted.iter().zip(published).all(|(wanted, published)| {
            *wanted == published.as_ref().map(|(_, shortest)| *shortest)
        });
        if unchanged {
            return None;
        }
        let (frunk_core::hlist_pat![tickets, core], _) = Take::<
            frunk_core::HList![Self, SendStrategyCore<SendStrategyOf<T, L>>],
            It,
        >::take(lineage);
        for (space, wanted) in PacketNumberSpaceKind::ALL.into_iter().zip(wanted) {
            let slot = &mut tickets.published[space_index(space)];
            if slot.as_ref().map(|(_, shortest)| *shortest) == wanted {
                continue;
            }
            // the old ticket goes after the new intent is in, so the space
            // is never without one while an ACK frame is due
            let old = slot.take();
            if let Some(shortest) = wanted {
                let ticket = core
                    .strategy_mut()
                    .publish_to(AckIntent::new(space, shortest), AnyActiveLinkPath.into());
                *slot = Some((ticket, shortest));
            }
            drop(old);
        }
        None
    }
}

// ---- the PING of a probe timeout ----

/// What publishing a probe's PING on a link path's planner gives back for
/// `T` and `L`.
pub type ProbePingTicketOf<T, L> =
    <LinkPathSendPlannerOf<T, L> as PublishOutcome<ProbePingIntent, PlannerLinkPath>>::Outcome;

/// The PINGs a link path's last probe timeout published, in the link
/// path's recovery layer: what publishing each gave back, by packet number
/// space. The next probe timeout drops them before it publishes its own,
/// and they go with the recovery layer.
pub struct ProbePingTickets<K> {
    published: [Option<K>; 3],
}

impl<K> fmt::Debug for ProbePingTickets<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let published = self.published.each_ref().map(Option::is_some);
        f.debug_struct("ProbePingTickets")
            .field("published", &published)
            .finish()
    }
}

impl<K> Default for ProbePingTickets<K> {
    fn default() -> Self {
        Self {
            published: [None, None, None],
        }
    }
}

impl<K> ProbePingTickets<K> {
    /// Whether a PING of `space` was published by the last probe timeout.
    pub fn is_published(&self, space: PacketNumberSpaceKind) -> bool {
        self.published[space_index(space)].is_some()
    }

    /// Drop the tickets of the last probe timeout and publish a PING in each
    /// of `spaces` on `planner`.
    pub(crate) fn probe<P, Idx>(
        &mut self,
        planner: &mut P,
        spaces: impl IntoIterator<Item = PacketNumberSpaceKind>,
    ) where
        P: Publish<ProbePingIntent, Idx>
            + PublishOutcome<ProbePingIntent, PlannerLinkPath, Outcome = K>,
    {
        self.published = [None, None, None];
        for space in spaces {
            self.published[space_index(space)] = Some(planner.publish(ProbePingIntent::new(space)));
        }
    }
}

/// A recovery layer starts with no probe.
impl<T: Choices, L> Build<T, L, layer::Recovery, ()> for ProbePingTickets<ProbePingTicketOf<T, L>>
where
    L: LineagePartList<T>,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    LinkPathSendPlannerOf<T, L>: PublishOutcome<ProbePingIntent, PlannerLinkPath>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Recovery>,
        _: &mut ArgsOf<T, L, layer::Recovery>,
    ) -> Self {
        Self::default()
    }
}

impl<K> PassiveDataComponent for ProbePingTickets<K> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(next: u64, largest_acked: Option<u64>) -> Option<NextPacketNumber> {
        Some(NextPacketNumber {
            next: PacketNumber::new(next).unwrap(),
            largest_acked: largest_acked.map(|largest| PacketNumber::new(largest).unwrap()),
        })
    }

    #[test]
    fn a_packet_takes_its_header_with_the_shortest_connection_id_and_its_tag() {
        let overheads = packet_overheads(
            Some(8),
            4,
            1200,
            next(0, None),
            next(0, None),
            next(0, None),
            Role::Server,
        );
        // the first byte, the version, both connection IDs with their
        // lengths, an empty token's length, a Length field of two bytes for
        // 1200, a packet number of one byte, the three bytes of payload the
        // header protection sample needs after it, and the tag
        assert_eq!(
            overheads.initial,
            Some(1 + 4 + 1 + 8 + 1 + 4 + 1 + 2 + 1 + 3 + 16)
        );
        assert_eq!(
            overheads.handshake,
            Some(1 + 4 + 1 + 8 + 1 + 4 + 2 + 1 + 3 + 16)
        );
        assert_eq!(overheads.one_rtt, Some(1 + 8 + 1 + 3 + 16));
        assert_eq!(overheads.zero_rtt, None);
        assert!(!overheads.expands_every_initial);
    }

    #[test]
    fn the_packet_number_and_the_length_field_take_what_they_need() {
        // 301 packets not acknowledged take two bytes (RFC 9000 Appendix
        // A.2), and the sample two more of the payload; one past the
        // largest acknowledged, one byte and three of the payload
        let overheads = packet_overheads(
            Some(8),
            8,
            16384,
            next(300, None),
            next(300, Some(299)),
            None,
            Role::Client,
        );
        assert_eq!(
            overheads.initial,
            Some(1 + 4 + 1 + 8 + 1 + 8 + 1 + 4 + 2 + 2 + 16)
        );
        assert_eq!(
            overheads.handshake,
            Some(1 + 4 + 1 + 8 + 1 + 8 + 4 + 1 + 3 + 16)
        );
        assert_eq!(overheads.one_rtt, None, "no keys to send with");
        assert!(overheads.expands_every_initial);
    }

    #[test]
    fn the_header_protection_sample_takes_what_the_packet_number_leaves_of_four_bytes() {
        // a zero-length connection ID: the first byte, a packet number of
        // one byte, which leaves three bytes of the four to the payload
        // (RFC 9001 §5.4.2), and the tag; a packet number of four bytes
        // leaves none
        let short = packet_overheads(Some(0), 0, 1200, None, None, next(0, None), Role::Server);
        assert_eq!(short.one_rtt, Some(1 + 1 + 3 + 16));
        let long = packet_overheads(
            Some(0),
            0,
            1200,
            None,
            None,
            next(1 << 24, Some(0)),
            Role::Server,
        );
        assert_eq!(long.one_rtt, Some(1 + 4 + 16));
    }

    #[test]
    fn nothing_is_sent_without_a_connection_id_to_send_with() {
        let overheads = packet_overheads(
            None,
            8,
            1200,
            next(0, None),
            next(0, None),
            next(0, None),
            Role::Client,
        );
        assert_eq!(
            overheads,
            PacketOverheads {
                expands_every_initial: true,
                ..PacketOverheads::default()
            }
        );
    }
}
