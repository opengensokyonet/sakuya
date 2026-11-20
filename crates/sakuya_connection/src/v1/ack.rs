//! Receiving an ACK frame: what it settles of what a logical path sent.
//!
//! An ACK frame acknowledges packet numbers of the packet number space of
//! the packet it came in. [`receive_ack`] handles it in two layers, and
//! gives feedback only once the whole frame is handled (RFC 9002 §6.1,
//! Appendix A.7):
//!
//! 1. The logical path checks that the frame acknowledges no packet number
//!    the space has not sent yet; such a frame ends the connection with
//!    PROTOCOL_VIOLATION (RFC 9000 §13.1). It takes the records of the
//!    acknowledged ranges out of the space's send journals, dropping first
//!    what is past its retention: a record still sent is newly
//!    acknowledged, one declared lost is acknowledged late. It moves the
//!    space's largest and smallest acknowledged packet numbers outward. In
//!    the Application Data space the frame is checked against the 1-RTT
//!    key generations first, and may confirm the current sending one, as
//!    the [`key_update`](super::key_update) module says.
//! 2. Each link path of the logical path with a recovery layer then takes
//!    its own packets out of its loss detection state for the space. The
//!    link path of the largest acknowledged packet gets an RTT sample when
//!    that packet is newly acknowledged and a newly acknowledged packet is
//!    ack-eliciting (RFC 9002 §5.1), from the arrival of the datagram, with
//!    the acknowledgment delay decoded by the peer's `ack_delay_exponent`.
//!    Its lent congestion controller then hears, in order, of the packets
//!    declared lost before and acknowledged late, as one call for each
//!    batch they were declared lost in; of the packets the frame declares
//!    lost, by the packet and time thresholds, as one congestion event, with
//!    persistent congestion, which the RTT estimate hears of too; and of the
//!    packets newly acknowledged, each step once what it settles left the
//!    bytes in flight. A link path whose packets were newly acknowledged has
//!    its permits past the window cleared, and its probe timeout's backoff
//!    too, except at a client not yet sure the server has validated its
//!    address (RFC 9002 §6.2.1); the pacer of each is refilled to the
//!    arrival.
//! 3. Last, every summary of the acknowledged packets goes back to its
//!    frame source as delivered, and then every summary of the packets
//!    declared lost as lost; those packets go back to the send journals,
//!    which keep their records for three probe timeouts of the space for a
//!    late acknowledgment.
//!
//! A frame that newly acknowledges nothing only acknowledges late: no RTT
//! sample, no loss detection, no backoff cleared (Appendix A.7).
//!
//! The ECN counts of a frame that increases the largest acknowledged packet
//! number of the space are compared with those of the last such frame of
//! the space, at the logical path, and the link path that has marked
//! packets outstanding in the space validates them before its losses are
//! detected, an increase of the CE count being a congestion event of its
//! lent controller, as the [`ecn`](super::ecn) module says. Each link path
//! then counts its newly acknowledged marked packets, by the packets its
//! own loss detection state had, and, once they go back to the send
//! journals, the marked packets it declared lost.
//!
//! Not here yet: an acknowledgment of a packet number the send journals
//! skipped, which they cannot tell yet.
use core::{ops::RangeInclusive, time::Duration};

use frunk_core::hlist_pat;
use sakuya_link::{EcnMarking, Link};
use sakuya_recovery::{
    congestion::{CongestionContext, CongestionController, InFlightPacket},
    factory::{LendCongestion, RecoveryFactory},
    loss::{LossThresholds, loss_delay},
    loss_detection::{LossDetectionState, Outstanding},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pmtu::{PmtuPolicy, PmtuProbeFailure},
    receive_journals::ReceivedEcnCounts,
    rtt::{RttEstimator, RttSample, effective_ack_delay},
    send_journals::{SendJournals, SentPacketState},
};
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{HList, Selector},
    v1::{
        frame::ack::{AckFrame, EcnCounts},
        packet_number::PacketNumber,
        role::Role,
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace,
            integer::{AckDelayExponent, MaxAckDelay, MaxUdpPayloadSize},
        },
    },
};
use snafu::{ResultExt as _, ensure};

use super::{
    Choices, EventsOf, Side,
    component_events::{AckReceived, CongestionChanged, PmtuConcluded, RttSampled},
    confirmation::HandshakeConfirmation,
    ecn::{EcnAck, LinkPathEcnState, ack_counts},
    error::{
        KeyUpdateSnafu, RejectedZeroRttPacketAcknowledgedSnafu, UnsentPacketAcknowledgedSnafu,
        V1ConnectionErrorOf,
    },
    events::{ConnectionEventSink, ConnectionEvents, LostPacket, RecoveryMetrics},
    feedback::LineageFeedback,
    key_phase::KeyPhaseNumbers,
    key_update::ack_received,
    keys::OneRttKeys,
    link::LinkClone,
    loss_detection::{LossFacts, declare_lost, hand_back_lost},
    parameters::PeerTransportParameters,
    pto::ProbeTimeout,
    receive::space_of,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, OthersOf, PmtuOf, RecoveryFactoryOf, RttOf,
        datagram_size_limits, lend_congestion, peer_max_udp_payload_size, refill,
    },
    send::SendTypes,
    send_planning::{ComponentPublishing, HostSendStrategyTypes},
    spaces::{DEFAULT_MAX_ACK_DELAY, SendJournalsOf, peer_max_ack_delay},
    streams::send::StreamIntent,
    zero_rtt_rejection::ZeroRttRejection,
};
use crate::v1::SendParametersOf;
use crate::v1::StreamSetFamilyOf;
use crate::{
    call::CallBundle,
    clock::{InstantOf, LinkIdOf},
    component::LineageOf,
    component_event::Happened,
    dispatch::DispatchFacts,
    error::ConnectionErrorsOf,
    feedback::FeedbackSummariesOf,
    frame_source::{EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts},
    layer::{self, LogicalPath, NodeKey},
    others::OtherNodes,
    share::{FlatMut, FlatRef, LineageLists, LineagePartList, LinkPathIdentifierOf, NodeData},
    take::{GetAt, ReadEach, TakeEach},
};

/// What receiving an ACK frame reads from the connection node: the
/// thresholds of loss detection, whether the handshake is confirmed, and
/// the peer's transport parameters.
pub type AckReads<L> = HList![
    LossThresholds,
    HandshakeConfirmation,
    PeerTransportParameters<TransportParameterSlots<L>>,
    ZeroRttRejection
];

/// What receiving an ACK frame takes from the recovery layer of each link
/// path, with the loss detection states of the controller's `S` and `Ls`.
pub type AckRecoveryTakes<T, L, S, Ls> = HList![
    RttOf<T, L>,
    CongestionPartOf<T, L>,
    PmtuOf<T, L>,
    LinkPathCongestionState<InstantOf<T>>,
    PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
    ProbeTimeout<InstantOf<T>>,
    LinkPathEcnState<InstantOf<T>>
];

/// Receive `frame`, an ACK frame of the packet that `packet` tells of, on
/// the logical path that `lineage` and `others` are the lend of; the steps
/// are those of the [module documentation](self).
///
/// The positions are found from the composition: `Ij` of the send
/// journals, `In` of the packet number states, `If` of the recovery
/// factory, `Ir` of what [`AckReads`] lists, `Io` of the 1-RTT keys and
/// `Ikp` of the key phase numbers, among the components of the logical
/// path's lineage; `Ide`, `Ima` and `Ipp` of the peer's
/// `ack_delay_exponent`, `max_ack_delay` and `max_udp_payload_size` among
/// the transport parameters; `Il` of the link's clone in an entry; `Ik` of
/// what [`AckRecoveryTakes`] lists in a recovery layer, and `Jx` and `Jr`
/// of the stored part of congestion control and the RTT estimate there;
/// `Hf` of each part's frame sources in the rest, for feedback, and `Is`
/// of the components of the established layer the frame sources find
/// ([`EstablishedSourceComponentsOfParts`]), which the feedback borrows.
///
/// # Errors
///
/// - [`ConnectionError::UnsentPacketAcknowledged`]: the frame acknowledges
///   a packet not sent yet.
/// - [`ConnectionError::RejectedZeroRttPacketAcknowledged`]: after the
///   server rejected 0-RTT, the frame acknowledges a 0-RTT packet.
/// - [`ConnectionError::KeyUpdate`]: a frame in a packet protected with
///   older 1-RTT keys acknowledges a packet sealed with newer ones.
///
/// Nothing is settled then.
///
/// [`ConnectionError::UnsentPacketAcknowledged`]: super::error::ConnectionError::UnsentPacketAcknowledged
/// [`ConnectionError::KeyUpdate`]: super::error::ConnectionError::KeyUpdate
/// [`ConnectionError::RejectedZeroRttPacketAcknowledged`]: super::error::ConnectionError::RejectedZeroRttPacketAcknowledged
pub fn receive_ack<
    'v,
    T,
    L,
    B,
    S,
    Ls,
    Ij,
    In,
    If,
    Ir,
    Io,
    Ikp,
    Iev,
    Ide,
    Ima,
    Ipp,
    Il,
    Ik,
    Jx,
    Jr,
    Hf,
    Is,
>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    frame: &AckFrame,
    packet: &DispatchFacts<InstantOf<T>, LinkPathIdentifierOf<T, L>>,
) -> Result<(), V1ConnectionErrorOf<L>>
where
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
    TransportParameterSlots<L>: Selector<Option<AckDelayExponent>, Ide>
        + Selector<Option<MaxAckDelay>, Ima>
        + Selector<Option<MaxUdpPayloadSize>, Ipp>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + ReadEach<AckReads<L>, Ir>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    L: ConnectionErrorsOf,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    L: EstablishedSourceComponentsOf<T, L>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Is>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Il>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, AckRecoveryTakes<T, L, S, Ls>, Ik>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
{
    let space = space_of(packet.level());
    let at = packet.at();
    let largest = frame.largest_acknowledged().get();
    let ranges: Vec<RangeInclusive<PacketNumber>> = frame.packet_ranges().collect();

    // the logical path: what the frame acknowledges of what was sent
    let Some(next) = lineage
        .get::<SendJournalsOf<T, L>, Ij>()
        .get(space)
        .map(SendJournals::next_packet_number)
    else {
        // a space is gone only where its keys were discarded before the
        // logical path was built, and no packet of it is processed
        return Ok(());
    };
    ensure!(
        largest < next,
        UnsentPacketAcknowledgedSnafu {
            space,
            largest,
            next,
            ecn_counts: frame.ecn_counts().is_some(),
        }
    );
    // a server that rejected 0-RTT processed none of its packets (RFC 9001
    // §4.6.2); they are the lowest numbers of the Application Data space
    if space == PacketNumberSpaceKind::ApplicationData {
        let hlist_pat![_, _, _, rejection] = (*lineage).read_each::<AckReads<L>, Ir>();
        let rejected = ranges.iter().find_map(|range| rejection.rejected_in(range));
        if let Some(acknowledged) = rejected {
            return RejectedZeroRttPacketAcknowledgedSnafu {
                acknowledged,
                ecn_counts: frame.ecn_counts().is_some(),
            }
            .fail();
        }
    }
    // the frames of the Application Data space come in 1-RTT packets only:
    // a 0-RTT packet carries no ACK frame (RFC 9000 §12.4)
    if let Some(opened_with) = packet.key_generation() {
        ack_received::<T::Crypto, _, _, Io, Ikp>(lineage, opened_with, largest, at)
            .context(KeyUpdateSnafu)?;
    }
    // Out of the lineage while the frame is handled, so that the summaries
    // of the packets declared lost can be lent to the frame sources beside
    // it; the empty journals left in their place take nothing meanwhile.
    let mut all_journals = lineage.get_mut::<SendJournalsOf<T, L>, Ij>();
    let Some(journals) = all_journals.get_mut(space) else {
        // invariant: the space was there above, and nothing since takes a
        // space away
        unreachable!("the space was there above")
    };
    let mut journals = core::mem::take(journals);
    journals.discard_expired(at);
    let mut acknowledged = Vec::new();
    for range in &ranges {
        acknowledged.extend(journals.take_acknowledged(range));
    }
    let newly = |state: &SentPacketState<InstantOf<T>>| matches!(state, SentPacketState::Sent(_));
    let any_newly = acknowledged.iter().any(|r| newly(&r.state));
    let eliciting = acknowledged
        .iter()
        .any(|r| newly(&r.state) && r.ack_eliciting);
    // the largest acknowledged packet, if newly acknowledged: the link path
    // it was sent on and when
    let largest_sent = acknowledged.iter().find_map(|r| match r.state {
        SentPacketState::Sent(sent_at) if r.number == largest => {
            Some((r.link_path.clone(), sent_at))
        }
        SentPacketState::Sent(_) | SentPacketState::Sealed | SentPacketState::Lost { .. } => None,
    });
    // when the largest acknowledged packet was sent, newly acknowledged or
    // acknowledged late: the reference of a congestion event of ECN-CE
    let largest_sent_at = acknowledged.iter().find_map(|r| match r.state {
        SentPacketState::Sent(sent_at)
        | SentPacketState::Lost {
            sent_at: Some(sent_at),
            ..
        } if r.number == largest => Some(sent_at),
        SentPacketState::Sent(_) | SentPacketState::Sealed | SentPacketState::Lost { .. } => None,
    });
    // the newly acknowledged marked packets, by packet number: each link
    // path counts those its loss detection state had
    let mut newly_marked: Vec<(PacketNumber, EcnMarking)> = acknowledged
        .iter()
        .filter(|r| newly(&r.state) && r.ecn != EcnMarking::NotEct)
        .map(|r| (r.number, r.ecn))
        .collect();
    newly_marked.sort_unstable_by_key(|(number, _)| *number);
    let smallest = ranges.last().map_or(largest, |range| *range.start());
    let mut ecn_counts = None;
    let numbers = lineage
        .get_mut::<PacketNumberSpaces<PacketNumberSpaceState>, In>()
        .get_mut(space)
        .map(|numbers| {
            ecn_counts = ack_counts(numbers, largest, frame.ecn_counts().map(reported_counts));
            numbers.on_ack(smallest, largest);
            *numbers
        });
    // the counts are of the one link path marking for the space
    let mut ecn_attributed = false;

    let hlist_pat![thresholds, confirmation, peer, _] = (*lineage).read_each::<AckReads<L>, Ir>();
    let thresholds = *thresholds;
    let confirmed = *confirmation == HandshakeConfirmation::Confirmed;
    let peer_max_ack_delay = peer_max_ack_delay::<L, Ima>(peer);
    let peer_udp = peer_max_udp_payload_size::<L, Ipp>(peer);
    // a client not yet sure the server has validated its address keeps
    // the backoff: it has neither the handshake confirmed nor an
    // acknowledgment of a Handshake packet (RFC 9002 §6.2.1, Appendix A.7)
    let backoff_resets = <T::Side as Side>::ROLE == Role::Server
        || confirmed
        || lineage
            .get::<PacketNumberSpaces<PacketNumberSpaceState>, In>()
            .handshake
            .as_ref()
            .and_then(PacketNumberSpaceState::largest_acked)
            .is_some();
    let reported = ack_delay(frame, peer_ack_delay_exponent::<L, Ide>(peer));
    let ack_delay = effective_ack_delay(
        space,
        reported,
        confirmed,
        peer_max_ack_delay.unwrap_or(DEFAULT_MAX_ACK_DELAY),
    );

    // each link path: its packets, its RTT, its congestion control
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
    let mut declared = Vec::new();
    for link in links {
        let identifier = L::link_path_identifier(&path, &link);
        let link_limit = others
            .link_entry::<HList![LinkClone<T::Link>], Il>(&link)
            .and_then(|hlist_pat![clone]| clone.0.max_datagram_size().ok());
        let sample_sent_at = largest_sent
            .as_ref()
            .filter(|(of, _)| eliciting && *of == identifier)
            .map(|(_, sent_at)| *sent_at);
        let mut factory = lineage.get_mut::<RecoveryFactoryOf<T, L>, If>();
        let batch = others.with_recovery_at::<AckRecoveryTakes<T, L, S, Ls>, Ik, _>(
            &path,
            &link,
            |hlist_pat![
                mut rtt,
                mut part,
                mut pmtu,
                mut state,
                mut detections,
                mut pto,
                mut ecn
            ],
             rest| {
                let detection = detections.get_mut(space)?;
                detection.discard_expired(at);
                let mut acked = Vec::new();
                for range in &ranges {
                    acked.extend(detection.take_acknowledged(range));
                }
                let (mut newly_ect0, mut newly_ect1) = (0u64, 0u64);
                for packet in &acked {
                    let Ok(index) = newly_marked.binary_search_by_key(&packet.number, |(n, _)| *n)
                    else {
                        continue;
                    };
                    match newly_marked[index].1 {
                        EcnMarking::Ect0 => newly_ect0 += 1,
                        EcnMarking::Ect1 => newly_ect1 += 1,
                        EcnMarking::NotEct => {}
                    }
                }
                let ecn_ack = match ecn_counts {
                    Some(counts) if !ecn_attributed && ecn.marks_for(space) => {
                        ecn_attributed = true;
                        Some(EcnAck {
                            counts,
                            newly_ect0,
                            newly_ect1,
                        })
                    }
                    _ => None,
                };
                let spurious = detection.take_spuriously_lost_batches(&ranges);
                let mut rtt_sampled = false;
                if let Some(sent_at) = sample_sent_at {
                    let min = rtt.estimate().min;
                    let via = packet.link_path().clone();
                    if let Some(sample) = RttSample::new(sent_at, at, ack_delay, min, via) {
                        state.rtt_sampled(*sample.at());
                        rtt.on_sample(sample);
                        rtt_sampled = true;
                    }
                }
                let estimate = rtt.estimate();
                let limits = datagram_size_limits(pmtu.conclusion(), peer_udp, link_limit);
                let max_datagram_size = limits.max_udp_payload();
                let facts = LossFacts {
                    now: at,
                    rtt: estimate,
                    thresholds,
                    peer_max_ack_delay,
                    limits,
                    rtt_sampled,
                };
                let newly_acked = !acked.is_empty();
                let mut concluded = false;
                let (batch, window) = lend_congestion::<T, L, B, Jx, Jr, _>(
                    &mut *factory,
                    &mut *part,
                    rest,
                    |mut access| {
                        let context = |bytes_in_flight| CongestionContext {
                            now: at,
                            bytes_in_flight,
                            rtt: estimate,
                            rtt_sampled,
                            max_datagram_size,
                        };
                        if !spurious.is_empty() {
                            let context = context(state.bytes_in_flight());
                            for (loss, packets) in spurious {
                                access.on_spurious_loss(loss, packets.into_iter(), &context);
                            }
                        }
                        // the ECN counts before losses (Appendix A.7)
                        if let Some(ecn_ack) = &ecn_ack {
                            let context = context(state.bytes_in_flight());
                            ecn.on_ack(ecn_ack, &mut access, largest_sent_at, &context);
                        }
                        // Appendix A.7 detects losses only when something is
                        // newly acknowledged, on every link path of the space
                        let batch = any_newly.then(|| {
                            let largest_acked = numbers
                                .as_ref()
                                .and_then(PacketNumberSpaceState::largest_acked)
                                .unwrap_or(largest);
                            let lost = detection.detect_lost(
                                at,
                                largest_acked,
                                loss_delay(&estimate, &thresholds),
                                thresholds.packet_threshold(),
                            );
                            declare_lost(
                                space,
                                lost,
                                numbers.as_ref(),
                                &mut *state,
                                &mut access,
                                &facts,
                                |size| {
                                    concluded |=
                                        pmtu.on_probe_failed(size, PmtuProbeFailure::Lost, at);
                                },
                            )
                        });
                        if acked_in_flight(&acked, &mut *state) {
                            let context = context(state.bytes_in_flight());
                            access
                                .on_acked(acked.into_iter().filter_map(in_flight_packet), &context);
                        }
                        // what congestion control allows changed anyway
                        let _refilled = refill(&mut access, at, &estimate, max_datagram_size);
                        // read only for the events, after the window's last change
                        let window = <EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED
                            .then(|| access.window());
                        (batch, window)
                    },
                );
                ecn.on_acknowledged(space, newly_ect0 + newly_ect1);
                if batch.as_ref().is_some_and(|batch| batch.persistent) {
                    rtt.on_persistent_congestion();
                }
                if newly_acked {
                    if backoff_resets {
                        pto.reset_backoff();
                    }
                    state.clear_probe_permits();
                }
                // as the acknowledgment left them, persistent congestion
                // included
                let metrics = window.map(|congestion_window| {
                    let estimate = rtt.estimate();
                    RecoveryMetrics {
                        min_rtt: estimate.min,
                        smoothed_rtt: estimate.smoothed,
                        latest_rtt: estimate.latest,
                        rtt_variance: estimate.variation,
                        congestion_window,
                        bytes_in_flight: state.bytes_in_flight(),
                    }
                });
                let on_link = acknowledged.iter().filter(|r| r.link_path == identifier);
                for probe in on_link.clone().filter(|r| r.pmtu_probe) {
                    state.on_pmtu_probe_settled();
                    concluded |= pmtu.on_probe_acked(probe.bytes, at);
                }
                let sizes = on_link.filter(|r| !r.pmtu_probe).map(|r| r.bytes);
                // Lost sizes come from the journals when their frames go
                // back to their sources, including packets with only ACKs.
                let deferred = match batch {
                    Some(batch) if !batch.numbers.is_empty() => {
                        Some((batch, sizes.collect::<Vec<_>>()))
                    }
                    _ => {
                        concluded |= pmtu.on_packets(sizes, core::iter::empty(), at);
                        None
                    }
                };
                Some((deferred, metrics, rtt_sampled, concluded))
            },
        );
        let Some((deferred, metrics, rtt_sampled, concluded)) = batch.flatten() else {
            continue;
        };
        // what the frame did to the link path's recovery layer
        let recovery = NodeKey::Recovery(path.clone(), link.clone());
        others.publish_at(&recovery, Happened::<CongestionChanged>::new());
        if rtt_sampled {
            others.publish_at(&recovery, Happened::<RttSampled>::new());
        }
        if concluded {
            others.publish_at(&recovery, Happened::<PmtuConcluded>::new());
        }
        if <EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED
            && let Some(events) = lineage
                .get_mut::<ConnectionEventSink<EventsOf<T, L>>, Iev>()
                .active::<InstantOf<T>>()
        {
            for &number in deferred.iter().flat_map(|(batch, _)| &batch.numbers) {
                events.packet_lost(
                    at,
                    &LostPacket {
                        space,
                        number: number.get(),
                        // the packet and time thresholds are not told apart here
                        trigger: None,
                    },
                );
            }
            if let Some(metrics) = &metrics {
                events.recovery_metrics(at, metrics);
            }
        }
        if let Some((batch, acked_sizes)) = deferred {
            declared.push((link, batch, acked_sizes));
        }
    }

    // the feedback, once the whole frame is handled: delivered first, then
    // lost; the components of the established layer the frame sources find
    // are borrowed for it, the layer recorded as taken
    let mut established =
        others.borrow_established_optional::<EstablishedSourceComponentsOfParts<T, L>, Is>();
    for record in acknowledged {
        LineageFeedback::<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>::delivered_each(
            lineage,
            &mut established,
            at,
            space,
            record.summaries,
        );
    }
    drop(established);
    for (link, batch, acked_sizes) in declared {
        let mut established =
            others.borrow_established_optional::<EstablishedSourceComponentsOfParts<T, L>, Is>();
        let mut lost_sizes = Vec::new();
        let marked_lost = hand_back_lost::<T, L, _, _, Hf>(
            &mut journals,
            lineage,
            &mut established,
            at,
            space,
            &batch,
            &mut lost_sizes,
        );
        drop(established);
        let concluded = others.with_recovery_at::<AckRecoveryTakes<T, L, S, Ls>, Ik, _>(
            &path,
            &link,
            |hlist_pat![_, _, mut pmtu, _, _, _, mut ecn], _| {
                ecn.on_lost(space, marked_lost);
                pmtu.on_packets(acked_sizes.into_iter(), lost_sizes.into_iter(), at)
            },
        );
        if concluded == Some(true) {
            others.publish_at(
                &NodeKey::Recovery(path.clone(), link),
                Happened::<PmtuConcluded>::new(),
            );
        }
    }
    if let Some(slot) = lineage.get_mut::<SendJournalsOf<T, L>, Ij>().get_mut(space) {
        *slot = journals;
    }
    lineage.publish(Happened::<AckReceived>::new());
    Ok(())
}

/// Take the bytes in flight of the newly acknowledged packets `acked` out
/// of `state`; whether any counted.
fn acked_in_flight<I: Copy, S>(
    acked: &[Outstanding<I, S>],
    state: &mut LinkPathCongestionState<I>,
) -> bool {
    let mut any = false;
    for packet in acked {
        if let Some(charge) = &packet.in_flight {
            state.remove_in_flight(charge.bytes);
            any = true;
        }
    }
    any
}

/// A newly acknowledged packet as its controller hears of it, if it counted
/// in the bytes in flight.
fn in_flight_packet<I, S>(packet: Outstanding<I, S>) -> Option<InFlightPacket<I, S>> {
    let charge = packet.in_flight?;
    Some(InFlightPacket {
        bytes: charge.bytes,
        sent_at: packet.sent_at,
        app_limited: charge.app_limited,
        sent_state: charge.sent_state,
    })
}

/// The ECN counts of an ACK frame as numbers.
fn reported_counts(counts: EcnCounts) -> ReceivedEcnCounts {
    ReceivedEcnCounts {
        ect0: counts.ect0.get().get(),
        ect1: counts.ect1.get().get(),
        ce: counts.ce.get().get(),
    }
}

/// The peer's `ack_delay_exponent`: its default, 3, while its transport
/// parameters are not known or when it left it out (RFC 9000 §18.2).
fn peer_ack_delay_exponent<L, I>(peer: &PeerTransportParameters<TransportParameterSlots<L>>) -> u64
where
    L: ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<AckDelayExponent>, I>,
{
    let exponent = peer
        .known()
        .and_then(|slots| *Selector::<Option<AckDelayExponent>, I>::get(slots))
        .unwrap_or_default();
    exponent.get().get()
}

/// The ACK Delay of `frame` as a duration: the field times 2 to the power
/// of `exponent`, in microseconds (RFC 9000 §19.3); a delay beyond what a
/// `u64` of microseconds holds saturates.
fn ack_delay(frame: &AckFrame, exponent: u64) -> Duration {
    let field = frame.ack_delay().get().get();
    // the exponent is at most 20 (RFC 9000 §18.2), which the parameter
    // checks when it is read
    let scale = 1u64.checked_shl(u32::try_from(exponent).unwrap_or(u32::MAX));
    Duration::from_micros(scale.map_or(u64::MAX, |scale| field.saturating_mul(scale)))
}
