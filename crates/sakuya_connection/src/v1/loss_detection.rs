//! The loss detection state of a link path's recovery layer, one for each
//! packet number space, and what a batch of losses does to the link path.
//!
//! The state of a space is [`LossDetectionState`]: the packets the link
//! accepted, by their consecutive sequence numbers on this link path. Its
//! deadline is the time threshold's: the earliest loss time among the
//! spaces. When it comes, each space whose loss time came is looked at
//! again, and the packets it declares lost are one batch.
//!
//! A batch leaves the bytes in flight. Its packets that count for
//! congestion go to the lent controller as one congestion event, are
//! tested for persistent congestion, and are kept to recognize a late
//! acknowledgment; the others leave without a signal.
//!
//! Not here yet: handing the lost packets to the send journals and to the
//! frame sources, and the ACK obligation's `ack_lost` for a lost packet
//! with only ACK frames.
use core::{ops::Add, ops::Sub, time::Duration};

use sakuya_link::Link;
use sakuya_recovery::{
    congestion::{CongestionContext, CongestionController, InFlightPacket, RemovedPacket},
    factory::{LendCongestion, RecoveryFactory},
    loss::{LossThresholds, loss_delay},
    loss_detection::{LossDetectionState, LostBatch, Outstanding},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    persistent_congestion::{
        LostPacket, establishes_persistent_congestion, persistent_congestion_duration,
    },
    pmtu::PmtuPolicy,
    pto::{ProbeCount, probe_timeout},
    rtt::{RttEstimate, RttEstimator},
};
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{HList, Selector},
    v1::{
        packet_number::PacketNumber,
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace,
            integer::{MaxAckDelay, MaxUdpPayloadSize},
        },
    },
};

use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    layer,
    others::OtherNodes,
    share::{FlatRef, LineageLists, NodeData},
    take::{GetAt, Take, TakeEach},
};

use super::{
    Choices,
    keys::{HandshakeKeys, InitialKeys},
    link::LinkClone,
    parameters::PeerTransportParameters,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, LossStateOf, OthersOf, PmtuOf,
        RecoveryFactoryOf, RttOf, SentStateOf, lend_congestion, max_datagram_size_in_use,
        peer_max_udp_payload_size,
    },
    spaces::{DEFAULT_MAX_ACK_DELAY, live_spaces, peer_max_ack_delay},
};

/// The loss detection states of a link path, one for each packet number
/// space, of the types the recovery factory of the choices `T` gives.
pub type LossDetectionOf<T, L> =
    PacketNumberSpaces<LossDetectionState<InstantOf<T>, SentStateOf<T, L>, LossStateOf<T, L>>>;

/// The facts of a link path that a batch of losses is handled with.
#[derive(Clone, Copy, Debug)]
pub(super) struct LossFacts<I> {
    /// The instant of this poll.
    pub(super) now: I,
    /// The link path's RTT estimate.
    pub(super) rtt: RttEstimate,
    /// The thresholds of loss detection.
    pub(super) thresholds: LossThresholds,
    /// The peer's `max_ack_delay`, `None` while it is not known.
    pub(super) peer_max_ack_delay: Option<Duration>,
    /// The maximum datagram size the link path uses.
    pub(super) max_datagram_size: usize,
}

/// Handle the batch `lost` of the space `space`, just declared lost on this
/// link path: its packets leave the bytes in flight; those that count for
/// congestion are one congestion event of `access`, and are kept as
/// declared lost for three probe timeouts of the space without backoff.
/// Returns whether the batch establishes persistent congestion, which the
/// caller tells the RTT estimate of.
///
/// A loss of the Handshake or Application Data space below every packet
/// number acknowledged in it, or before any was, does not count for
/// congestion (RFC 9002 §7.4, MAY): the peer may not have had the keys yet.
/// The packets are handed out oldest first, so these come first.
pub(super) fn declare_lost<I, S, Ls, A>(
    space: PacketNumberSpaceKind,
    mut lost: LostBatch<'_, I, S, Ls>,
    numbers: Option<&PacketNumberSpaceState>,
    state: &mut LinkPathCongestionState<I>,
    access: &mut A,
    facts: &LossFacts<I>,
) -> bool
where
    I: Ord + Copy + Add<Duration, Output = I> + Sub<Output = Duration>,
    Ls: Clone,
    A: CongestionController<I, SentState = S, LossState = Ls>,
{
    let ignored = |p: &Outstanding<I, S>| {
        space != PacketNumberSpaceKind::Initial
            && numbers.is_none_or(|n| n.loss_may_ignore_congestion(p.number))
    };
    // look at the batch before handing it out: what leaves the bytes in
    // flight, and whether the packets that count establish persistent
    // congestion
    let (mut any_ignored, mut any_counted) = (false, false);
    for packet in lost.packets() {
        let Some(charge) = &packet.in_flight else {
            continue;
        };
        state.remove_in_flight(charge.bytes);
        if ignored(packet) {
            any_ignored = true;
        } else {
            any_counted = true;
        }
    }
    let granularity = facts.thresholds.granularity();
    let persistent = any_counted
        && establishes_persistent_congestion(
            lost.packets()
                .filter(|p| p.in_flight.is_some() && !ignored(p))
                .map(|p| LostPacket {
                    seq: p.seq,
                    sent_at: p.sent_at,
                    ack_eliciting: p.ack_eliciting,
                }),
            persistent_congestion_duration(&facts.rtt, granularity, facts.peer_max_ack_delay),
            state.first_rtt_sample_at(),
        );
    let context = CongestionContext {
        now: facts.now,
        bytes_in_flight: state.bytes_in_flight(),
        rtt: facts.rtt,
        rtt_sampled: false,
        max_datagram_size: facts.max_datagram_size,
    };
    // Not here yet: a packet with only ACK frames goes to the ACK
    // obligation.
    if any_ignored {
        access.on_removed(
            core::iter::from_fn(|| {
                loop {
                    let packet = lost.next_if(ignored)?;
                    if let Some(charge) = packet.in_flight {
                        return Some(RemovedPacket {
                            bytes: charge.bytes,
                            sent_state: charge.sent_state,
                        });
                    }
                }
            }),
            &context,
        );
    }
    if !any_counted {
        return false;
    }
    let loss = access.on_lost(
        core::iter::from_fn(|| {
            loop {
                let packet = lost.next()?;
                if let Some(charge) = packet.in_flight {
                    lost.keep(packet.number, packet.sent_at, charge.bytes);
                    return Some(InFlightPacket {
                        bytes: charge.bytes,
                        sent_at: packet.sent_at,
                        app_limited: charge.app_limited,
                        sent_state: charge.sent_state,
                    });
                }
            }
        }),
        &context,
    );
    if persistent {
        access.on_persistent_congestion(&context);
    }
    if access.wants_recovery_send() {
        state.grant_probe_permits(ProbeCount::One);
    }
    let pto = probe_timeout(
        &facts.rtt,
        granularity,
        space,
        facts.peer_max_ack_delay.unwrap_or(DEFAULT_MAX_ACK_DELAY),
        0,
    );
    lost.finish(loss, facts.now + pto.saturating_mul(3));
    persistent
}

/// Each space whose keys are not discarded starts with nothing sent.
impl<T, L, S, Ls, Ii, Ih> Build<T, L, layer::Recovery, (Ii, Ih)>
    for PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>
where
    T: Choices,
    for<'v> L: LineageLists<'v, T>,
    for<'v> <L as LineageLists<'v, T>>::LinkPath:
        GetAt<InitialKeys<T::Crypto>, Ii> + GetAt<HandshakeKeys<T::Crypto>, Ih>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::Recovery>,
        _: &mut ArgsOf<T, L, layer::Recovery>,
    ) -> Self {
        live_spaces::<T, _, Ii, Ih, _>(parents, |_| LossDetectionState::new())
    }
}

/// The deadline is the earliest loss time among the spaces; it reads
/// itself, which the calls change. When it comes, each space whose loss
/// time came declares its packets lost by the time threshold, against the
/// largest packet number acknowledged in the space, and its losses are one
/// batch (RFC 9002 §6.1.2, Appendix A.10). The time threshold's batch has
/// the loss steps only.
///
/// Not here yet: handing the lost packets to the send journals and the
/// frame sources.
impl<T, L, S, Ls, Id, In, Ith, Ir, Ip, Ipr, Il, Ipp, Ima, It, Jx, Jr>
    DataComponent<T, L, layer::Recovery, ((Id, In, Ith, Ir), (Ip, Ipr, Il, Ipp, Ima), It, (Jx, Jr))>
    for PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>
where
    T: Choices,
    for<'v> L: LineageLists<'v, T>,
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
    for<'v> <L as LineageLists<'v, T>>::Recovery: GetAt<Self, Id>
        + GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>
        + GetAt<LossThresholds, Ith>
        + GetAt<RttOf<T, L>, Ir>
        + GetAt<PmtuOf<T, L>, Ip>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipr>
        + GetAt<LinkClone<T::Link>, Il>
        + TakeEach<
            'v,
            HList![
                RecoveryFactoryOf<T, L>,
                CongestionPartOf<T, L>,
                RttOf<T, L>,
                Self,
                LinkPathCongestionState<InstantOf<T>>
            ],
            It,
        >,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add::<Self>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Recovery>) -> Option<InstantOf<T>> {
        lineage
            .get::<Self, Id>()
            .iter()
            .filter_map(|(_, detection)| detection.loss_time())
            .min()
    }
    fn expire<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, layer::Recovery>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let facts = loss_facts::<T, L, Ith, Ir, Ip, Ipr, Il, Ipp, Ima, _>(&lineage, now);
        let numbers = lineage
            .get::<PacketNumberSpaces<PacketNumberSpaceState>, In>()
            .clone();
        let (frunk_core::hlist_pat![factory, part, rtt, spaces, state], _) =
            Take::<
                HList![
                    RecoveryFactoryOf<T, L>,
                    CongestionPartOf<T, L>,
                    RttOf<T, L>,
                    Self,
                    LinkPathCongestionState<InstantOf<T>>
                ],
                It,
            >::take(lineage);
        let delay = loss_delay(&facts.rtt, &facts.thresholds);
        let threshold = facts.thresholds.packet_threshold();
        let persistent =
            lend_congestion::<T, L, B, Jx, Jr, _>(factory, part, others, |mut access| {
                let mut persistent = false;
                for (space, detection) in spaces.iter_mut() {
                    if detection.loss_time().is_none_or(|at| at > now) {
                        continue;
                    }
                    let numbers = numbers.get(space);
                    // with nothing acknowledged nothing is eligible, and the loss
                    // time goes
                    let largest = numbers
                        .and_then(PacketNumberSpaceState::largest_acked)
                        .unwrap_or(PacketNumber::ZERO);
                    detection.discard_expired(now);
                    let lost = detection.detect_lost(now, largest, delay, threshold);
                    persistent |= declare_lost(space, lost, numbers, state, &mut access, &facts);
                }
                persistent
            });
        if persistent {
            rtt.on_persistent_congestion();
        }
        None
    }
}

/// The facts of the link path a batch of losses is handled with, read from
/// its recovery layer's lineage at `now`.
pub(super) fn loss_facts<T, L, Ith, Ir, Ip, Ipr, Il, Ipp, Ima, V>(
    lineage: &crate::take::Lineage<'_, V>,
    now: InstantOf<T>,
) -> LossFacts<InstantOf<T>>
where
    T: Choices,
    L: ParametersOf<TransportParameterSpace> + crate::share::LogicalPathKeys,
    TransportParameterSlots<L>:
        Selector<Option<MaxUdpPayloadSize>, Ipp> + Selector<Option<MaxAckDelay>, Ima>,
    V: GetAt<LossThresholds, Ith>
        + GetAt<RttOf<T, L>, Ir>
        + GetAt<PmtuOf<T, L>, Ip>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipr>
        + GetAt<LinkClone<T::Link>, Il>,
{
    let peer = lineage.get::<PeerTransportParameters<TransportParameterSlots<L>>, Ipr>();
    let max_datagram_size = max_datagram_size_in_use(
        lineage.get::<PmtuOf<T, L>, Ip>().conclusion(),
        peer_max_udp_payload_size::<L, Ipp>(peer),
        lineage
            .get::<LinkClone<T::Link>, Il>()
            .0
            .max_datagram_size()
            .ok(),
    );
    LossFacts {
        now,
        rtt: lineage.get::<RttOf<T, L>, Ir>().estimate(),
        thresholds: *lineage.get::<LossThresholds, Ith>(),
        peer_max_ack_delay: peer_max_ack_delay::<L, Ima>(peer),
        max_datagram_size,
    }
}
