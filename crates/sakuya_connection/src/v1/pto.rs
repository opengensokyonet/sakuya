//! The probe timeout of a link path (RFC 9002 §6.2).
//!
//! The component keeps the backoff count only; its deadline is computed
//! when it is read, from the link path's RTT estimate, its loss detection
//! state and the facts of the connection. What to send when it expires is
//! the lent [`PtoPolicy`](sakuya_recovery::pto::PtoPolicy)'s choice.

use core::{ops::Add, time::Duration};

use sakuya_recovery::{
    factory::{LendCongestion, RecoveryFactory},
    loss::LossThresholds,
    loss_detection::LossDetectionState,
    packet_number_space::{
        PacketNumberSpaceKind, PacketNumberSpaceSet, PacketNumberSpaceState, PacketNumberSpaces,
    },
    pto::{PtoAction, PtoExpiry, PtoPolicy, probe_timeout},
    rtt::{RttEstimate, RttEstimator},
    send_journals::SendJournals,
};
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{HList, Selector},
    v1::transport_parameters::{
        TransportParameterSlots, TransportParameterSpace,
        integer::{MaxAckDelay, MaxUdpPayloadSize},
    },
};

use crate::{
    call::CallBundle,
    clock::{CheckedAdd, InstantOf},
    component::{
        ArgsOf, Build, ComponentTypeList, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf,
    },
    feedback::FeedbackSummariesOf,
    layer,
    others::OtherNodes,
    send_strategy::{Publish, SendStrategy, SendStrategyTypes},
    share::{FlatRef, LineageLists, LineagePartList, NodeData},
    take::{GetAt, ReadEach, Take, TakeEach},
};

use super::{
    Choices, Side,
    amplification::AntiAmplification,
    confirmation::HandshakeConfirmation,
    feedback::CoreLentFeedback,
    keys::HandshakeKeys,
    link::LinkFacts,
    loss_detection::{LossFactsReads, declare_lost, hand_back_lost, loss_facts},
    parameters::PeerTransportParameters,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, OthersOf, RecoveryFactoryOf, RttOf,
        lend_congestion,
    },
    send::{ProbePingIntent, SendTypes},
    send_planning::{
        LinkPathPlanner, LinkPathSendPlannerOf, ProbePingTicketOf, ProbePingTickets, SendStrategyOf,
    },
    spaces::{DEFAULT_MAX_ACK_DELAY, SendJournalsOf, peer_max_ack_delay},
};
use crate::role::LinkPathRole;

/// The probe timeout of a link path (RFC 9002 §6.2): how many times it
/// expired since the last acknowledgment that acknowledged something new,
/// when it last expired, and since when a client probes with nothing
/// ack-eliciting outstanding.
///
/// The deadline is computed from it when it is read. Only an `Active` link
/// path sets one; a link path whose loss detection waits on the time
/// threshold in any space sets none (§6.2.1), nor does one whose address
/// the anti-amplification limit holds back (§6.2.2.1). The backoff has no
/// upper bound; the duration saturates.
///
/// A timeout counts from the later of the last ack-eliciting packet sent in
/// its space and the last expiry, so that a deadline is never in the past
/// after one expires: once a probe is sent, its send time is the later one,
/// as in Appendix A.9.
///
/// A client whose peer has not acknowledged any of its Handshake packets,
/// before the handshake is confirmed, keeps a probe timeout even with
/// nothing ack-eliciting outstanding (§6.2.2.1, MUST): it counts from when
/// that started, in the Handshake space once there are Handshake keys and
/// in the Initial space before (Appendix A.8).
///
/// `I` is the instant of the connection's clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProbeTimeout<I> {
    backoff: u32,
    expired_at: Option<I>,
    anti_deadlock_since: Option<I>,
}

impl<I: Ord + Copy + Add<Duration, Output = I> + CheckedAdd<Duration>> ProbeTimeout<I> {
    /// Not expired yet.
    pub const fn new() -> Self {
        Self {
            backoff: 0,
            expired_at: None,
            anti_deadlock_since: None,
        }
    }

    /// How many times it expired without a new acknowledgment.
    pub const fn backoff(&self) -> u32 {
        self.backoff
    }

    /// When it last expired, `None` before it did.
    pub const fn expired_at(&self) -> Option<I> {
        self.expired_at
    }

    /// Since when a client probes with nothing ack-eliciting outstanding,
    /// `None` while it does not.
    pub const fn anti_deadlock_since(&self) -> Option<I> {
        self.anti_deadlock_since
    }

    /// It expired at `now`: the backoff grows by one (RFC 9002 §6.2.1,
    /// MUST).
    pub fn expired(&mut self, now: I) {
        self.backoff = self.backoff.saturating_add(1);
        self.expired_at = Some(now);
    }

    /// An ACK frame newly acknowledged packets of the link path: the backoff
    /// is reset (RFC 9002 §6.2.1, Appendix A.7), and the next timeout counts
    /// from the last ack-eliciting packet sent in its space, not from the
    /// last expiry, as Appendix A.8 sets the timer.
    pub fn reset_backoff(&mut self) {
        self.backoff = 0;
        self.expired_at = None;
    }

    /// The client probes with nothing ack-eliciting outstanding since
    /// `since`, or, with `None`, no longer does.
    pub fn set_anti_deadlock_since(&mut self, since: Option<I>) {
        self.anti_deadlock_since = since;
    }

    /// When a timeout counts from whose last ack-eliciting packet was sent
    /// at `sent_at`.
    fn counts_from(&self, sent_at: I) -> I {
        self.expired_at.map_or(sent_at, |at| at.max(sent_at))
    }

    /// The instant it expires and the space whose timeout it is: the
    /// earliest among the spaces with ack-eliciting packets outstanding,
    /// leaving out the Application Data space before the handshake is
    /// confirmed (§6.2.1, Appendix A.8); or, while a client probes with
    /// nothing outstanding, the one of `anti_deadlock_space`. `None` with
    /// neither. A space whose timeout is past the last instant `I` can
    /// represent gives none: with the backoff that high, the idle timeout
    /// ended the connection long before.
    ///
    /// `peer_max_ack_delay` is the peer's in the Application Data space.
    pub(super) fn earliest<S, Ls>(
        &self,
        spaces: &PacketNumberSpaces<LossDetectionState<I, S, Ls>>,
        rtt: &RttEstimate,
        granularity: Duration,
        peer_max_ack_delay: Duration,
        confirmation: HandshakeConfirmation,
        anti_deadlock_space: PacketNumberSpaceKind,
    ) -> Option<(I, PacketNumberSpaceKind)> {
        let duration =
            |space| probe_timeout(rtt, granularity, space, peer_max_ack_delay, self.backoff);
        if let Some(since) = self.anti_deadlock_since {
            let space = anti_deadlock_space;
            return Some((self.counts_from(since).checked_add(duration(space))?, space));
        }
        spaces
            .iter()
            .filter(|(space, _)| {
                *space != PacketNumberSpaceKind::ApplicationData
                    || confirmation == HandshakeConfirmation::Confirmed
            })
            .filter(|(_, detection)| detection.has_ack_eliciting_outstanding())
            .filter_map(|(space, detection)| {
                let sent_at = detection.last_ack_eliciting_sent_at()?;
                Some((
                    self.counts_from(sent_at).checked_add(duration(space))?,
                    space,
                ))
            })
            .min_by_key(|(at, _)| *at)
    }
}

/// The spaces with ack-eliciting packets outstanding on the link path.
fn in_flight_spaces<I, S, Ls>(
    spaces: &PacketNumberSpaces<LossDetectionState<I, S, Ls>>,
) -> PacketNumberSpaceSet
where
    I: Ord + Copy + Add<Duration, Output = I>,
{
    spaces
        .iter()
        .filter(|(_, detection)| detection.has_ack_eliciting_outstanding())
        .map(|(space, _)| space)
        .collect()
}

/// A link path starts with no backoff.
impl<T: Choices, L> Build<T, L, layer::Recovery, ()> for ProbeTimeout<InstantOf<T>>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Recovery>,
        _: &mut ArgsOf<T, L, layer::Recovery>,
    ) -> Self {
        Self::new()
    }
}

/// The deadline is computed when it is read, from what it reads: itself,
/// the RTT estimate and the loss detection state of the layer, the role of
/// the link path, the anti-amplification limit and the facts of its
/// logical link, the handshake confirmation and the Handshake keys, the
/// packet number spaces' state, the peer's transport parameters and the
/// thresholds of loss detection.
///
/// Its reread starts and ends a client's probing with nothing
/// ack-eliciting outstanding, at the instant of the poll that finds it
/// starts or ends.
///
/// When it expires the backoff grows by one and the lent policy says what
/// to do. A probe grants as many permits past the window as datagrams and
/// publishes a PING on the link path's planner in each space the policy
/// gives and in the expired one, dropping the last probe's; a
/// choice to declare the packets in flight lost is a batch of losses in
/// each space, as the time threshold's, handed back to the send journals
/// and the parts as the time threshold's is.
///
/// Not here yet: declaring the packets in flight lost without asking the
/// policy while the link path cannot send 1200 bytes.
impl<T, L, S, Ls, Ipt, Ir, If, Ipp, Ima, It, Jx, Jr, Hf, Ip>
    DataComponent<T, L, layer::Recovery, ((Ipt, Ir, If), (Ipp, Ima), It, (Jx, Jr), Hf, Ip)>
    for ProbeTimeout<InstantOf<T>>
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf,
    L: ParametersOf<TransportParameterSpace>,
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
    for<'v> <L as LineageLists<'v, T>>::Recovery: GetAt<ProbeTimeout<InstantOf<T>>, Ipt>
        + ReadEach<ProbeTimeoutReads<T, L, S, Ls>, Ir>
        + ReadEach<LossFactsReads<T, L>, If>
        + TakeEach<'v, ProbeTimeoutTakes<T, L, S, Ls>, It>,
    for<'v> <<L as LineageLists<'v, T>>::Recovery as TakeEach<
        'v,
        ProbeTimeoutTakes<T, L, S, Ls>,
        It,
    >>::Rest: CoreLentFeedback<T, L, Hf>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    LinkPathSendPlannerOf<T, L>: Publish<ProbePingIntent, Ip>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add_each::<ProbeTimeoutReads<T, L, S, Ls>>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Recovery>) -> Option<InstantOf<T>> {
        earliest::<T, L, S, Ls, Ima>(lineage.read_each::<ProbeTimeoutReads<T, L, S, Ls>, Ir>())
            .map(|(at, _)| at)
    }
    fn expire<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, layer::Recovery>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let reads = lineage.read_each::<ProbeTimeoutReads<T, L, S, Ls>, Ir>();
        let (_, expired_space) = earliest::<T, L, S, Ls, Ima>(reads)?;
        let frunk_core::hlist_pat![_, _, _, _, _, _, _, _, _, _, numbers] = reads;
        let numbers = numbers.clone();
        let facts = loss_facts::<T, L, Ipp, Ima, _, If>(&lineage, now);
        let (
            frunk_core::hlist_pat![
                pto, factory, part, rtt, spaces, state, journals, planner, pings
            ],
            mut rest,
        ) = Take::<ProbeTimeoutTakes<T, L, S, Ls>, It>::take(lineage);
        pto.expired(now);
        let expiry = PtoExpiry {
            at: now,
            expired_space,
            in_flight_spaces: in_flight_spaces(spaces),
            backoff: pto.backoff(),
            rtt: facts.rtt,
        };
        let mut probed = None;
        let batches = lend_congestion::<T, L, B, Jx, Jr, _>(factory, part, others, |mut access| {
            let mut batches = Vec::new();
            match access.on_pto_expired(&expiry) {
                PtoAction::Probe { datagrams, spaces } => {
                    state.grant_probe_permits(datagrams);
                    probed = Some(spaces.with(expired_space));
                }
                PtoAction::MarkInFlightLost => {
                    for (space, detection) in spaces.iter_mut() {
                        detection.discard_expired(now);
                        let batch = declare_lost(
                            space,
                            detection.take_all(),
                            numbers.get(space),
                            state,
                            &mut access,
                            &facts,
                        );
                        batches.push((space, batch));
                    }
                }
            }
            batches
        });
        if let Some(spaces) = probed {
            pings.probe::<_, Ip>(planner.planner_mut(), spaces.iter());
        }
        for (space, batch) in &batches {
            if batch.persistent {
                rtt.on_persistent_congestion();
            }
            let Some(journals) = journals.get_mut(*space) else {
                continue;
            };
            journals.discard_expired(now);
            hand_back_lost::<T, L, _, Hf>(journals, &mut rest, now, *space, batch);
        }
        None
    }
    fn reread<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Recovery>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let reads = lineage.read_each::<ProbeTimeoutReads<T, L, S, Ls>, Ir>();
        let probes = probes_with_nothing_outstanding::<T, L, S, Ls>(reads);
        let pto = reads.head;
        let since = match (probes, pto.anti_deadlock_since()) {
            (true, None) => Some(now),
            (false, Some(_)) => None,
            (true, Some(_)) | (false, None) => return None,
        };
        lineage
            .get_mut::<ProbeTimeout<InstantOf<T>>, Ipt>()
            .set_anti_deadlock_since(since);
        None
    }
}

/// What the probe timeout's expiry takes out of a recovery layer's lineage.
type ProbeTimeoutTakes<T, L, S, Ls> = HList![
    ProbeTimeout<InstantOf<T>>,
    RecoveryFactoryOf<T, L>,
    CongestionPartOf<T, L>,
    RttOf<T, L>,
    PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
    LinkPathCongestionState<InstantOf<T>>,
    SendJournalsOf<T, L>,
    LinkPathPlanner<LinkPathSendPlannerOf<T, L>>,
    ProbePingTickets<ProbePingTicketOf<T, L>>
];

/// What the probe timeout reads: its deadline and its reread look at these,
/// and it is reread when one of them changes.
type ProbeTimeoutReads<T, L, S, Ls> = HList![
    ProbeTimeout<InstantOf<T>>,
    PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
    RttOf<T, L>,
    LossThresholds,
    HandshakeConfirmation,
    PeerTransportParameters<TransportParameterSlots<L>>,
    LinkPathRole<InstantOf<T>>,
    AntiAmplification,
    LinkFacts,
    HandshakeKeys<<T as Choices>::Crypto>,
    PacketNumberSpaces<PacketNumberSpaceState>
];

/// The borrows of what the probe timeout reads.
type ProbeTimeoutRefs<'s, T, L, S, Ls> =
    <ProbeTimeoutReads<T, L, S, Ls> as ComponentTypeList>::Refs<'s>;

/// Whether the client whose probe timeout reads `reads` probes with nothing
/// ack-eliciting outstanding: its peer has not acknowledged any of its
/// Handshake packets, the handshake is not confirmed, and nothing
/// ack-eliciting is outstanding on the link path (RFC 9002 §6.2.2.1,
/// Appendix A.8). A server never does: it assumes the client validated its
/// address.
fn probes_with_nothing_outstanding<T, L, S, Ls>(reads: ProbeTimeoutRefs<'_, T, L, S, Ls>) -> bool
where
    T: Choices,
    L: ParametersOf<TransportParameterSpace> + crate::share::LogicalPathKeys + 'static,
    S: 'static,
    Ls: 'static,
{
    let frunk_core::hlist_pat![_, detection, _, _, confirmation, _, _, _, _, _, numbers] = reads;
    !T::Side::peer_validates_address_implicitly()
        && *confirmation != HandshakeConfirmation::Confirmed
        && numbers
            .get(PacketNumberSpaceKind::Handshake)
            .is_none_or(|handshake| handshake.largest_acked().is_none())
        && !detection
            .iter()
            .any(|(_, detection)| detection.has_ack_eliciting_outstanding())
}

/// The instant the probe timeout that reads `reads` expires, and the space
/// whose timeout it is.
fn earliest<T, L, S, Ls, Ima>(
    reads: ProbeTimeoutRefs<'_, T, L, S, Ls>,
) -> Option<(InstantOf<T>, PacketNumberSpaceKind)>
where
    T: Choices,
    L: ParametersOf<TransportParameterSpace> + crate::share::LogicalPathKeys + 'static,
    S: 'static,
    Ls: 'static,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
{
    let frunk_core::hlist_pat![
        pto,
        spaces,
        rtt,
        thresholds,
        confirmation,
        peer,
        role,
        amplification,
        facts,
        handshake_keys,
        _
    ] = reads;
    if *role != LinkPathRole::Active {
        return None;
    }
    // the time threshold comes first (§6.2.1, Appendix A.8)
    if spaces.iter().any(|(_, d)| d.loss_time().is_some()) {
        return None;
    }
    // a server at the limit waits for the client's next datagram
    // (§6.2.2.1)
    if amplification.credit(facts.validation) == Some(0) {
        return None;
    }
    let peer_max_ack_delay = peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
    let anti_deadlock_space = if handshake_keys.send().is_some() {
        PacketNumberSpaceKind::Handshake
    } else {
        PacketNumberSpaceKind::Initial
    };
    pto.earliest(
        spaces,
        &rtt.estimate(),
        thresholds.granularity(),
        peer_max_ack_delay,
        *confirmation,
        anti_deadlock_space,
    )
}
