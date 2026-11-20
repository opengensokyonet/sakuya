//! The retirement of a logical path's Initial and Handshake packet number
//! spaces once the keys of their level are discarded (RFC 9002 §6.4,
//! Appendix A.11).
//!
//! [`PacketNumberSpaceRetirement`] is a component of each logical path
//! that subscribes to the Initial and the Handshake keys discarded. When it
//! finds the keys of a level discarded while the logical path still has its
//! space, it retires the space, once:
//!
//! 1. On each link path of the logical path with a recovery layer, the
//!    packets of the space still outstanding leave the bytes in flight, and
//!    the lent congestion controller hears of them as removed without a
//!    signal; the loss detection state of the space goes, with its loss
//!    time and the packets it keeps as declared lost; and the probe
//!    timeout's backoff is reset. The probe timeout computes its deadline
//!    when it is read, from the spaces left, so the driver reads one that
//!    may be earlier (§6.2.2).
//! 2. The logical path's packet number state, receive journals, ACK
//!    obligation and send journals of the space go. The summaries of the
//!    frames the send journals keep go with them: their frame sources hear
//!    nothing of these packets. That the space retired is published at the
//!    logical path.
//!
//! The Application Data space is never retired. Every way the keys are
//! discarded retires the space the same way: a server processing its first
//! Handshake packet, a client sealing its first, the handshake being
//! confirmed, and the connection draining. A closing connection keeps the
//! receiving half of the keys, and the space with it, until they are
//! discarded.
//!
//! A packet of the space that the sending call sealed but its link had not
//! accepted yet is not outstanding: the sending call removes it from the
//! bytes in flight without a signal when the link accepts it or gives it
//! up.
use frunk_core::hlist_pat;
use sakuya_link::Link;
use sakuya_recovery_v1::{
    congestion::{CongestionContext, CongestionController, RemovedPacket},
    factory::{LendCongestion, RecoveryFactory},
    loss_detection::LossDetectionState,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pmtu::PmtuPolicy,
    receive_journals::ReceiveJournals,
    rtt::RttEstimator,
};
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{HList, Selector},
};
use sakuya_wire_v1::transport_parameters::{
    TransportParameterSlots, TransportParameterSpace, integer::MaxUdpPayloadSize,
};

use super::{
    Choices,
    component_events::{CongestionChanged, KeysDiscarded, SpaceRetired, level},
    ecn::LinkPathEcnState,
    keys::{HandshakeKeys, InitialKeys},
    link::LinkClone,
    parameters::PeerTransportParameters,
    pto::ProbeTimeout,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, OthersOf, PmtuOf, RecoveryFactoryOf, RttOf,
        lend_congestion, max_datagram_size_in_use, peer_max_udp_payload_size,
    },
    spaces::{AckObligationsOf, SendJournalsOf},
};
use crate::{
    call::CallBundle,
    clock::{InstantOf, LinkIdOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    component_event::{EventSubscriptions, Happened, TriggeredEvents},
    feedback::FeedbackSummariesOf,
    layer::{self, LogicalPath, NodeKey},
    others::OtherNodes,
    share::{FlatMut, FlatRef, LineageLists, LineagePartList, NodeData},
    take::{GetAt, TakeEach},
};

/// The component of a logical path that retires its Initial and Handshake
/// packet number spaces once the keys of their level are discarded, as the
/// [module documentation](self) says.
///
/// It holds nothing: whether a space is retired is whether the logical
/// path still has it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketNumberSpaceRetirement;

/// A space that can be retired: the Initial or the Handshake space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetiringSpace {
    Initial,
    Handshake,
}

impl RetiringSpace {
    /// Take the value of this space out of `spaces`; `None` if it is gone
    /// already.
    fn kind(self) -> PacketNumberSpaceKind {
        match self {
            Self::Initial => PacketNumberSpaceKind::Initial,
            Self::Handshake => PacketNumberSpaceKind::Handshake,
        }
    }

    fn take<X>(self, spaces: &mut PacketNumberSpaces<X>) -> Option<X> {
        match self {
            Self::Initial => spaces.initial.take(),
            Self::Handshake => spaces.handshake.take(),
        }
    }
}

/// A logical path starts with nothing retired: the spaces whose keys were
/// discarded before it was built are not there.
impl<T: Choices, L> Build<T, L, layer::LogicalPath, ()> for PacketNumberSpaceRetirement
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        Self
    }
}

/// What retiring a space takes from the recovery layer of each link path,
/// with the loss detection states of the controller's `S` and `Ls`.
type RetirementRecoveryTakes<T, L, S, Ls> = HList![
    RttOf<T, L>,
    CongestionPartOf<T, L>,
    PmtuOf<T, L>,
    LinkPathCongestionState<InstantOf<T>>,
    PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
    ProbeTimeout<InstantOf<T>>,
    LinkPathEcnState<InstantOf<T>>
];

/// It has no deadline. It subscribes to the Initial and the Handshake keys
/// discarded, and its handler retires each space whose keys it finds
/// discarded while the logical path still has the space.
///
/// The positions are found from the composition: `Ii` and `Ih` of the
/// Initial and Handshake keys; `In`, `Ir`, `Ia` and `Ij` of the packet
/// number states, the receive journals, the ACK obligations and the send
/// journals; `If` of the recovery factory, `Ip` of the peer's transport
/// parameters and `Ipp` of its `max_udp_payload_size` among them, `Il` of
/// the link's clone in an entry; `Ik` of what retiring takes from a
/// recovery layer, and `Jx` and `Jr` of the stored part of congestion
/// control and the RTT estimate there.
impl<T, L, S, Ls, Ii, Ih, In, Ir, Ia, Ij, If, Ip, Ipp, Il, Ik, Jx, Jr>
    DataComponent<
        T,
        L,
        layer::LogicalPath,
        ((Ii, Ih), (In, Ir, Ia, Ij), (If, Ip, Ipp, Il), Ik, (Jx, Jr)),
    > for PacketNumberSpaceRetirement
where
    T: Choices,
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
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
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ir>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Il>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, RetirementRecoveryTakes<T, L, S, Ls>, Ik>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<KeysDiscarded<level::Initial>>()
            .add::<KeysDiscarded<level::Handshake>>();
    }

    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let spaces = lineage.get::<PacketNumberSpaces<PacketNumberSpaceState>, In>();
        let initial = spaces.initial.is_some()
            && matches!(
                lineage.get::<InitialKeys<T::Crypto>, Ii>(),
                InitialKeys::Discarded
            );
        let handshake = spaces.handshake.is_some()
            && matches!(
                lineage.get::<HandshakeKeys<T::Crypto>, Ih>(),
                HandshakeKeys::Discarded
            );
        let retiring = [
            (RetiringSpace::Initial, initial),
            (RetiringSpace::Handshake, handshake),
        ];
        for (space, discarded) in retiring {
            if discarded {
                retire::<T, L, B, S, Ls, In, Ir, Ia, Ij, If, Ip, Ipp, Il, Ik, Jx, Jr>(
                    &mut lineage,
                    others,
                    space,
                    now,
                );
            }
        }
        None
    }
}

/// Retire `space` of the logical path that `lineage` and `others` are the
/// lend of, at `now`: on each of its link paths with a recovery layer
/// first, then in the logical path.
#[allow(clippy::too_many_arguments)]
fn retire<'v, T, L, B, S, Ls, In, Ir, Ia, Ij, If, Ip, Ipp, Il, Ik, Jx, Jr>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    space: RetiringSpace,
    now: InstantOf<T>,
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
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ir>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Il>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, RetirementRecoveryTakes<T, L, S, Ls>, Ik>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
{
    let NodeKey::LogicalPath(path) = others.here().clone() else {
        unreachable!("a logical path's lend carries its key")
    };
    let links: Vec<LinkIdOf<T>> = others
        .link_path_keys()
        .filter_map(|key| match key {
            NodeKey::LinkPath(of, link) if *of == path => Some(link.clone()),
            _ => None,
        })
        .collect();
    let peer_limit = peer_max_udp_payload_size::<L, Ipp>(
        lineage.get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>(),
    );
    for link in links {
        let link_limit = others
            .link_entry::<HList![LinkClone<T::Link>], Il>(&link)
            .and_then(|hlist_pat![clone]| clone.0.max_datagram_size().ok());
        let mut factory = lineage.get_mut::<RecoveryFactoryOf<T, L>, If>();
        let removed = others.with_recovery_at::<RetirementRecoveryTakes<T, L, S, Ls>, Ik, _>(
            &path,
            &link,
            |hlist_pat![
                rtt,
                mut part,
                pmtu,
                mut state,
                mut detections,
                mut pto,
                mut ecn
            ],
             rest| {
                // Appendix A.11 resets the backoff whatever was in flight
                pto.reset_backoff();
                // its marked packets leave with the rest
                ecn.on_space_retired(space.kind());
                let Some(mut detection) = space.take(&mut *detections) else {
                    return false;
                };
                let removed: Vec<RemovedPacket<S>> = detection
                    .take_all()
                    .filter_map(|packet| {
                        let charge = packet.in_flight?;
                        Some(RemovedPacket {
                            bytes: charge.bytes,
                            sent_state: charge.sent_state,
                        })
                    })
                    .collect();
                if removed.is_empty() {
                    return false;
                }
                for packet in &removed {
                    state.remove_in_flight(packet.bytes);
                }
                let context = CongestionContext {
                    now,
                    bytes_in_flight: state.bytes_in_flight(),
                    rtt: rtt.estimate(),
                    rtt_sampled: false,
                    max_datagram_size: max_datagram_size_in_use(
                        pmtu.conclusion(),
                        peer_limit,
                        link_limit,
                    ),
                };
                lend_congestion::<T, L, B, Jx, Jr, _>(
                    &mut *factory,
                    &mut *part,
                    rest,
                    |mut access| {
                        access.on_removed(removed.into_iter(), &context);
                    },
                );
                true
            },
        );
        if removed == Some(true) {
            others.publish_at(
                &NodeKey::Recovery(path.clone(), link),
                Happened::<CongestionChanged>::new(),
            );
        }
    }
    space.take(&mut *lineage.get_mut::<PacketNumberSpaces<PacketNumberSpaceState>, In>());
    space.take(&mut *lineage.get_mut::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ir>());
    space.take(&mut *lineage.get_mut::<AckObligationsOf<T>, Ia>());
    space.take(&mut *lineage.get_mut::<SendJournalsOf<T, L>, Ij>());
    lineage.publish(Happened::<SpaceRetired>::new());
}
