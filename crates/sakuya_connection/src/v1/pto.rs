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
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    layer,
    others::OtherNodes,
    share::{FlatRef, LineageLists, NodeData},
    take::{GetAt, Take, TakeEach},
};

use super::{
    Choices, Side,
    amplification::AntiAmplification,
    confirmation::HandshakeConfirmation,
    keys::HandshakeKeys,
    link::{LinkClone, LinkFacts},
    loss_detection::{declare_lost, loss_facts},
    parameters::PeerTransportParameters,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, OthersOf, PmtuOf, RecoveryFactoryOf, RttOf,
        lend_congestion,
    },
    role::LinkPathRole,
    spaces::{DEFAULT_MAX_ACK_DELAY, peer_max_ack_delay},
};

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
    for<'v> L: LineageLists<'v, T>,
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
/// to do. A probe grants as many permits past the window as datagrams; a
/// choice to declare the packets in flight lost is a batch of losses in
/// each space, as the time threshold's.
///
/// Not here yet: the PING wanted in each space to probe, which goes out
/// through the link path's send planner; and declaring the packets in
/// flight lost without asking the policy while the link path cannot send
/// 1200 bytes.
impl<T, L, S, Ls, Ipt, Id, Ir, Ith, Ihc, Ipr, Ima, Irl, Iaa, Ilf, Ihk, Ip, Il, Ipp, In, It, Jx, Jr>
    DataComponent<
        T,
        L,
        layer::Recovery,
        (
            (Ipt, Id, Ir, Ith),
            (Ihc, Ipr, Ima, Irl),
            (Iaa, Ilf, Ihk),
            (Ip, Il, Ipp, In, It),
            (Jx, Jr),
        ),
    > for ProbeTimeout<InstantOf<T>>
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
    for<'v> <L as LineageLists<'v, T>>::Recovery: GetAt<ProbeTimeout<InstantOf<T>>, Ipt>
        + GetAt<PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>, Id>
        + GetAt<RttOf<T, L>, Ir>
        + GetAt<LossThresholds, Ith>
        + GetAt<HandshakeConfirmation, Ihc>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipr>
        + GetAt<LinkPathRole<InstantOf<T>>, Irl>
        + GetAt<AntiAmplification, Iaa>
        + GetAt<LinkFacts, Ilf>
        + GetAt<HandshakeKeys<T::Crypto>, Ihk>
        + GetAt<PmtuOf<T, L>, Ip>
        + GetAt<LinkClone<T::Link>, Il>
        + GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>
        + TakeEach<
            'v,
            HList![
                ProbeTimeout<InstantOf<T>>,
                RecoveryFactoryOf<T, L>,
                CongestionPartOf<T, L>,
                RttOf<T, L>,
                PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
                LinkPathCongestionState<InstantOf<T>>
            ],
            It,
        >,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
{
    fn reads(reads: &mut ReadSet) {
        reads
            .add::<ProbeTimeout<InstantOf<T>>>()
            .add::<RttOf<T, L>>()
            .add::<PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>>()
            .add::<LinkPathRole<InstantOf<T>>>()
            .add::<AntiAmplification>()
            .add::<LinkFacts>()
            .add::<HandshakeConfirmation>()
            .add::<HandshakeKeys<T::Crypto>>()
            .add::<PacketNumberSpaces<PacketNumberSpaceState>>()
            .add::<PeerTransportParameters<TransportParameterSlots<L>>>()
            .add::<LossThresholds>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Recovery>) -> Option<InstantOf<T>> {
        earliest::<T, L, S, Ls, _, Ipt, Id, Ir, Ith, Ihc, Ipr, Ima, Irl, Iaa, Ilf, Ihk>(lineage)
            .map(|(at, _)| at)
    }
    fn expire<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, layer::Recovery>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let (_, expired_space) =
            earliest::<T, L, S, Ls, _, Ipt, Id, Ir, Ith, Ihc, Ipr, Ima, Irl, Iaa, Ilf, Ihk>(
                &lineage,
            )?;
        let facts = loss_facts::<T, L, Ith, Ir, Ip, Ipr, Il, Ipp, Ima, _>(&lineage, now);
        let numbers = lineage
            .get::<PacketNumberSpaces<PacketNumberSpaceState>, In>()
            .clone();
        let (frunk_core::hlist_pat![pto, factory, part, rtt, spaces, state], _) =
            Take::<
                HList![
                    ProbeTimeout<InstantOf<T>>,
                    RecoveryFactoryOf<T, L>,
                    CongestionPartOf<T, L>,
                    RttOf<T, L>,
                    PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
                    LinkPathCongestionState<InstantOf<T>>
                ],
                It,
            >::take(lineage);
        pto.expired(now);
        let expiry = PtoExpiry {
            at: now,
            expired_space,
            in_flight_spaces: in_flight_spaces(spaces),
            backoff: pto.backoff(),
            rtt: facts.rtt,
        };
        let persistent =
            lend_congestion::<T, L, B, Jx, Jr, _>(factory, part, others, |mut access| {
                match access.on_pto_expired(&expiry) {
                    PtoAction::Probe {
                        datagrams,
                        spaces: _,
                    } => {
                        // Not here yet: a PING wanted in each of the spaces
                        // given, and in the expired one even if left out.
                        state.grant_probe_permits(datagrams);
                        false
                    }
                    PtoAction::MarkInFlightLost => {
                        let mut persistent = false;
                        for (space, detection) in spaces.iter_mut() {
                            detection.discard_expired(now);
                            persistent |= declare_lost(
                                space,
                                detection.take_all(),
                                numbers.get(space),
                                state,
                                &mut access,
                                &facts,
                            );
                        }
                        persistent
                    }
                }
            });
        if persistent {
            rtt.on_persistent_congestion();
        }
        None
    }
    fn reread<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Recovery>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let probes = probes_with_nothing_outstanding::<T, S, Ls, _, Id, Ihc, In>(&lineage);
        let since = lineage
            .get::<ProbeTimeout<InstantOf<T>>, Ipt>()
            .anti_deadlock_since();
        match (probes, since) {
            (true, None) => lineage
                .get_mut::<ProbeTimeout<InstantOf<T>>, Ipt>()
                .set_anti_deadlock_since(Some(now)),
            (false, Some(_)) => lineage
                .get_mut::<ProbeTimeout<InstantOf<T>>, Ipt>()
                .set_anti_deadlock_since(None),
            (true, Some(_)) | (false, None) => {}
        }
        None
    }
}

/// Whether the client whose recovery layer's lineage is `lineage` probes
/// with nothing ack-eliciting outstanding: its peer has not acknowledged
/// any of its Handshake packets, the handshake is not confirmed, and
/// nothing ack-eliciting is outstanding on the link path (RFC 9002
/// §6.2.2.1, Appendix A.8). A server never does: it assumes the client
/// validated its address.
fn probes_with_nothing_outstanding<T, S, Ls, V, Id, Ihc, In>(
    lineage: &crate::take::Lineage<'_, V>,
) -> bool
where
    T: Choices,
    V: GetAt<PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>, Id>
        + GetAt<HandshakeConfirmation, Ihc>
        + GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>,
{
    !T::Side::peer_validates_address_implicitly()
        && *lineage.get::<HandshakeConfirmation, Ihc>() != HandshakeConfirmation::Confirmed
        && lineage
            .get::<PacketNumberSpaces<PacketNumberSpaceState>, In>()
            .get(PacketNumberSpaceKind::Handshake)
            .is_none_or(|handshake| handshake.largest_acked().is_none())
        && !lineage
            .get::<PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>, Id>()
            .iter()
            .any(|(_, detection)| detection.has_ack_eliciting_outstanding())
}

/// The instant the probe timeout of the link path whose recovery layer's
/// lineage is `lineage` expires, and the space whose timeout it is.
fn earliest<T, L, S, Ls, V, Ipt, Id, Ir, Ith, Ihc, Ipr, Ima, Irl, Iaa, Ilf, Ihk>(
    lineage: &crate::take::Lineage<'_, V>,
) -> Option<(InstantOf<T>, PacketNumberSpaceKind)>
where
    T: Choices,
    L: ParametersOf<TransportParameterSpace> + crate::share::LogicalPathKeys,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    V: GetAt<ProbeTimeout<InstantOf<T>>, Ipt>
        + GetAt<PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>, Id>
        + GetAt<RttOf<T, L>, Ir>
        + GetAt<LossThresholds, Ith>
        + GetAt<HandshakeConfirmation, Ihc>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipr>
        + GetAt<LinkPathRole<InstantOf<T>>, Irl>
        + GetAt<AntiAmplification, Iaa>
        + GetAt<LinkFacts, Ilf>
        + GetAt<HandshakeKeys<T::Crypto>, Ihk>,
{
    if *lineage.get::<LinkPathRole<InstantOf<T>>, Irl>() != LinkPathRole::Active {
        return None;
    }
    let spaces = lineage.get::<PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>, Id>();
    // the time threshold comes first (§6.2.1, Appendix A.8)
    if spaces.iter().any(|(_, d)| d.loss_time().is_some()) {
        return None;
    }
    // a server at the limit waits for the client's next datagram
    // (§6.2.2.1)
    let validation = lineage.get::<LinkFacts, Ilf>().validation;
    if lineage.get::<AntiAmplification, Iaa>().credit(validation) == Some(0) {
        return None;
    }
    let peer = lineage.get::<PeerTransportParameters<TransportParameterSlots<L>>, Ipr>();
    let peer_max_ack_delay = peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
    let anti_deadlock_space = if lineage
        .get::<HandshakeKeys<T::Crypto>, Ihk>()
        .send()
        .is_some()
    {
        PacketNumberSpaceKind::Handshake
    } else {
        PacketNumberSpaceKind::Initial
    };
    lineage.get::<ProbeTimeout<InstantOf<T>>, Ipt>().earliest(
        spaces,
        &lineage.get::<RttOf<T, L>, Ir>().estimate(),
        lineage.get::<LossThresholds, Ith>().granularity(),
        peer_max_ack_delay,
        *lineage.get::<HandshakeConfirmation, Ihc>(),
        anti_deadlock_space,
    )
}
