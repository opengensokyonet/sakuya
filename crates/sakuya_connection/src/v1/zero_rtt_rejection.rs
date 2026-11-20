//! What a logical path keeps of a rejected 0-RTT (RFC 9001 §4.6.2, RFC
//! 9002 §6.4).
//!
//! [`ZeroRttRejection`] is a component of each logical path that
//! subscribes to [`ZeroRttRejected`], which a client's advancing call
//! publishes when its handshake completes and the server had rejected its
//! 0-RTT. Its handler, once:
//!
//! 1. Notes the packet number the Application Data space numbers its next
//!    packet with. Every packet below it is a 0-RTT packet: the 1-RTT keys
//!    to send with are installed in the same lend as the event is
//!    published, so no 1-RTT packet was sealed yet, and none of them was
//!    processed by the server.
//! 2. Takes the records of those packets out of the space's send journals,
//!    on each link path of the logical path, those sealed but not handed
//!    to their link yet among them. The frames whose sources are outside
//!    the established layer, such as NEW_CONNECTION_ID, go back to them as
//!    lost, unless they went back already: the server never processed
//!    them. The frames of the established layer go with the records: their
//!    sources were in the layer that ended for the rejection, and the one
//!    built in its place starts anew (RFC 9001 §4.6.2). The default send
//!    strategy puts nothing but the established layer's frames and PING in
//!    a 0-RTT packet; another may put more there.
//! 3. On each link path with a recovery layer, the outstanding packets of
//!    the space leave the bytes in flight, and the lent congestion
//!    controller hears of them as removed without a signal; the loss time
//!    of the space goes, and its marked packets are no longer outstanding
//!    in the ECN state. The probe timeout's backoff stays: neither RFC
//!    resets it here.
//!
//! A 0-RTT packet sealed before the rejection and handed to its link, or
//! given up, after it has no record any more, and its frames went back
//! with the records: the sending call removes it from the bytes in flight
//! without a signal, as a packet of a retired space.
//!
//! Afterwards an ACK frame that acknowledges a packet below the noted
//! number is [`ConnectionError::RejectedZeroRttPacketAcknowledged`], a
//! PROTOCOL_VIOLATION (RFC 9001 §4.6.2, SHOULD).
//!
//! [`ConnectionError::RejectedZeroRttPacketAcknowledged`]: super::error::ConnectionError::RejectedZeroRttPacketAcknowledged
use core::ops::RangeInclusive;

use frunk_core::hlist_pat;
use sakuya_link::Link;
use sakuya_recovery::{
    congestion::{CongestionContext, CongestionController, RemovedPacket},
    factory::{LendCongestion, RecoveryFactory},
    loss_detection::LossDetectionState,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    pmtu::PmtuPolicy,
    rtt::RttEstimator,
    send_journals::SendJournals,
};
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{HList, Selector},
};
use sakuya_wire_v1::{
    packet_number::PacketNumber,
    transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, integer::MaxUdpPayloadSize,
    },
};

use super::{
    Choices, SendParametersOf, StreamSetFamilyOf,
    component_events::{CongestionChanged, ZeroRttRejected},
    ecn::LinkPathEcnState,
    feedback::LineageFeedback,
    link::LinkClone,
    parameters::PeerTransportParameters,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, OthersOf, PmtuOf, RecoveryFactoryOf, RttOf,
        lend_congestion, max_datagram_size_in_use, peer_max_udp_payload_size,
    },
    send::SendTypes,
    send_planning::{ComponentPublishing, HostSendStrategyTypes},
    spaces::SendJournalsOf,
    streams::send::StreamIntent,
};
use crate::{
    call::CallBundle,
    clock::{InstantOf, LinkIdOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    component_event::{EventSubscriptions, Happened, TriggeredEvents},
    feedback::FeedbackSummariesOf,
    frame_source::{EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts},
    layer::{self, LogicalPath, NodeKey},
    others::OtherNodes,
    share::{FlatMut, FlatRef, LineageLists, LineagePartList, NodeData},
    take::{GetAt, OptionalRefs, TakeEach},
};

/// Whether the server rejected this client's 0-RTT, as a logical path
/// keeps it (`ZeroRttRejection`); see the [module documentation](self).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ZeroRttRejection {
    /// No 0-RTT was rejected: a server's logical path, or a client's that
    /// sent no 0-RTT, or whose 0-RTT was accepted, or whose handshake has
    /// not completed yet.
    #[default]
    NotRejected,
    /// The server rejected 0-RTT: every packet number of the Application
    /// Data space below `first_after` was a 0-RTT packet.
    Rejected {
        /// The packet number of the first packet sealed after the
        /// rejection.
        first_after: PacketNumber,
    },
}

impl ZeroRttRejection {
    /// Whether the server rejected 0-RTT.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    /// The smallest packet number of `range` that was a rejected 0-RTT
    /// packet; `None` when the range has none, or no 0-RTT was rejected.
    pub fn rejected_in(&self, range: &RangeInclusive<PacketNumber>) -> Option<PacketNumber> {
        match self {
            Self::Rejected { first_after } if range.start() < first_after => Some(*range.start()),
            Self::NotRejected | Self::Rejected { .. } => None,
        }
    }
}

/// A logical path starts with no 0-RTT rejected.
impl<T: Choices, L> Build<T, L, layer::LogicalPath, ()> for ZeroRttRejection
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        Self::NotRejected
    }
}

/// What a rejected 0-RTT takes from the recovery layer of each link path,
/// with the loss detection states of the controller's `S` and `Ls`.
type RejectionRecoveryTakes<T, L, S, Ls> = HList![
    RttOf<T, L>,
    CongestionPartOf<T, L>,
    PmtuOf<T, L>,
    LinkPathCongestionState<InstantOf<T>>,
    PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
    LinkPathEcnState<InstantOf<T>>
];

/// It has no deadline. It subscribes to the 0-RTT rejected, and its
/// handler does what the [module documentation](self) says, once.
///
/// The positions are found from the composition: `I` of the component
/// itself and `Ij` of the send journals; `If` of the recovery factory, `Ip`
/// of the peer's transport parameters and `Ipp` of its
/// `max_udp_payload_size` among them, `Il` of the link's clone in an
/// entry; `Ik` of what it takes from a recovery layer, and `Jx` and `Jr` of
/// the stored part of congestion control and the RTT estimate there; `Hf`
/// of each part's frame sources, for the frames that go back.
impl<T, L, S, Ls, I, Ij, If, Ip, Ipp, Il, Ik, Jx, Jr, Hf>
    DataComponent<T, L, layer::LogicalPath, ((I, Ij), (If, Ip, Ipp, Il), Ik, (Jx, Jr), Hf)>
    for ZeroRttRejection
where
    T: Choices,
    L: LineagePartList<T>
        + FeedbackSummariesOf
        + ParametersOf<TransportParameterSpace>
        + EstablishedSourceComponentsOf<T, L>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<Self, I>
        + GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>
        + LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Il>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, RejectionRecoveryTakes<T, L, S, Ls>, Ik>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<ZeroRttRejected>();
    }

    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        if lineage.get::<Self, I>().is_rejected() {
            return None;
        }
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
        // the records, sealed ones among them
        let (first_after, records) = {
            let mut journals = lineage.get_mut::<SendJournalsOf<T, L>, Ij>();
            let space = &mut journals.application_data;
            let mut records = Vec::new();
            for link in &links {
                records.extend(space.take_link_path(&L::link_path_identifier(&path, link)));
            }
            (space.next_packet_number(), records)
        };
        *lineage.get_mut::<Self, I>() = Self::Rejected { first_after };
        // the frames of the sources outside the established layer go back
        // as lost; the established layer is not lent, so its frames go
        // with the records and do not reach the layer built anew
        let mut absent = EstablishedSourceComponentsOfParts::<T, L>::spread(None);
        LineageFeedback::<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>::lost_each(
            &mut lineage,
            &mut absent,
            now,
            PacketNumberSpaceKind::ApplicationData,
            records
                .iter()
                .filter(|record| !record.content_handed_back)
                .flat_map(|record| &record.summaries),
        );
        drop(records);
        let peer_limit = peer_max_udp_payload_size::<L, Ipp>(
            lineage.get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>(),
        );
        for link in links {
            let link_limit = others
                .link_entry::<HList![LinkClone<T::Link>], Il>(&link)
                .and_then(|hlist_pat![clone]| clone.0.max_datagram_size().ok());
            let mut factory = lineage.get_mut::<RecoveryFactoryOf<T, L>, If>();
            let removed = others.with_recovery_at::<RejectionRecoveryTakes<T, L, S, Ls>, Ik, _>(
                &path,
                &link,
                |hlist_pat![rtt, mut part, pmtu, mut state, mut detections, mut ecn], rest| {
                    // every marked packet of the space outstanding is a
                    // 0-RTT packet
                    ecn.on_zero_rtt_rejected();
                    let removed: Vec<RemovedPacket<S>> = detections
                        .application_data
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
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(n: u32) -> PacketNumber {
        PacketNumber::new(n.into()).unwrap()
    }

    #[test]
    fn a_range_starting_below_the_first_packet_after_the_rejection_acknowledges_0_rtt() {
        let rejected = ZeroRttRejection::Rejected {
            first_after: number(4),
        };
        assert_eq!(
            rejected.rejected_in(&(number(2)..=number(9))),
            Some(number(2))
        );
        assert_eq!(
            rejected.rejected_in(&(number(3)..=number(3))),
            Some(number(3))
        );
        assert_eq!(rejected.rejected_in(&(number(4)..=number(9))), None);
        assert_eq!(
            ZeroRttRejection::NotRejected.rejected_in(&(number(0)..=number(9))),
            None
        );
    }
}
