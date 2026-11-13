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
use sakuya_wire::{
    parameters::ParametersOf,
    parts::Selector,
    v1::{
        encryption_level::EncryptionLevel,
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace, integer::MaxUdpPayloadSize,
        },
    },
};

use sakuya_recovery::{
    ack_obligation::{AckDue, AckObligation},
    congestion::CongestionController,
    pacing::Pacer,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    pmtu::PmtuPolicy,
    receive_journals::ReceiveJournals,
};

use super::{
    AckObligationsOf, Choices, CloseCauseOf,
    amplification::AntiAmplification,
    close::CloseReasonRecord,
    confirmation::HandshakeConfirmation,
    keys::{HandshakeKeys, InitialKeys, OneRttKeys},
    link::{FirstLinkStart, LinkClone, LinkFacts},
    parameters::PeerTransportParameters,
    recovery::{CongestionPartOf, LinkPathCongestionState, PmtuOf, peer_max_udp_payload_size},
    role::LinkPathRole,
    send::{AckIntent, ProbePingIntent, SendTypes, shortest_ack_frame},
};
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, ReadSet,
        RequestOf,
    },
    layer::{self, NodeKey},
    others::OtherNodes,
    send_strategy::{
        AnyActiveLinkPath, DatagramLimits, LinkPathRoleKind, LinkPathSendPlanner, Observe,
        PlannerLinkPath, Publish, PublishOutcome, PublishTo, SendStrategy, SendStrategyTypes,
    },
    share::{FlatRef, LineageLists, LineagePartList, LogicalPathKeys, NodeData},
    take::{GetAt, ReadEach, Take, TakeEach},
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
/// role and the limits it was last told.
pub struct LinkPathPlanner<P> {
    planner: P,
    role: LinkPathRoleKind,
    limits: Option<DatagramLimits>,
}

impl<P> fmt::Debug for LinkPathPlanner<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkPathPlanner")
            .field("role", &self.role)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<P> LinkPathPlanner<P> {
    /// The planner.
    pub fn planner(&self) -> &P {
        &self.planner
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

/// A planner is told when its link path's role changes, and what the link
/// path can send whenever a component that limits it changes: the
/// anti-amplification credit, the peer's transport parameters, and the
/// congestion control, its fixed state and the datagram size probing
/// policy in the link path's recovery layer.
impl<T: Choices, L, Ip, Ir, It, Il, Ipp, Jc, Js, Jm>
    DataComponent<T, L, layer::LinkPath, (Ip, Ir, It, Il, Ipp, (Jc, Js, Jm))>
    for LinkPathPlanner<LinkPathSendPlannerOf<T, L>>
where
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace>,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    LinkPathSendPlannerOf<T, L>: Observe<DatagramLimits>,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, Ipp>,
    CongestionPartOf<T, L>: CongestionController<InstantOf<T>> + Pacer<InstantOf<T>>,
    for<'v> <L as LineageLists<'v, T>>::LinkPath: GetAt<Self, Ip>
        + GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + ReadEach<DatagramLimitsReads<T, L>, Il>
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
    }

    fn reread<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        debug_assert!(matches!(others.here(), NodeKey::LinkPath(..)));
        let role = lineage.get::<LinkPathRole<InstantOf<T>>, Ir>().kind();
        let limits = read_datagram_limits::<T, L, B, Il, Ipp, Jc, Js, Jm>(&lineage, others);
        let told = lineage.get::<Self, Ip>();
        if told.role == role && told.limits == Some(limits) {
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
/// that grows, so it is never planned for a packet its frame does not fit.
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
