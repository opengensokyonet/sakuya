//! The recovery layer of a link path: what the recovery factory makes for
//! it, the fixed state beside them, and how its congestion access is lent.
//!
//! The recovery factory ([`RecoveryFactory`]) is a component of the
//! connection node, made from its configuration when the connection is
//! made. When a link path's recovery layer is built, the factory makes the
//! layer's RTT estimate, the part of its congestion control it stores and
//! its datagram size probing policy, as one unit. The layer also holds the
//! fixed state the protocol defines around them
//! ([`LinkPathCongestionState`]).
//!
//! The types the choices give are not named here: their components are
//! implemented for any type of the trait, told apart by a marker in the
//! position the driver infers (`ChosenRttEstimator` and the like).
//!
//! Every use of a link path's congestion state goes through the factory's
//! [`LendCongestion`]: the fixed code takes the factory and this link
//! path's part, gives the other link paths read only as
//! [`OtherCongestionParts`], and uses what is lent.
use core::{fmt, marker::PhantomData};

use sakuya_link::{Link, MIN_DATAGRAM_SIZE};
use sakuya_recovery::{
    congestion::CongestionController,
    factory::{LendCongestion, RecoveryFactory},
    pacing::{Pacer, PacingInput},
    pmtu::PmtuPolicy,
    pto::ProbeCount,
    rtt::{RttEstimate, RttEstimator},
};
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{HList, Selector},
    v1::transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, integer::MaxUdpPayloadSize,
    },
};

use crate::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf, LinkIdOf},
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, ReadSet,
        RequestOf,
    },
    layer::{self, NodeKey},
    others::OtherNodes,
    share::{
        ConnectionArgsOf, FlatRef, LineageLists, LineagePartList, LinkPathIdentifierOf, NodeData,
        PathKey,
    },
    take::{GetAt, ReadEach, Take, TakeEach},
};

use super::{
    Choices, ConnectionArgs, link::LinkClone, loss_detection::LossFactsReads, own_args,
    parameters::PeerTransportParameters,
};

/// The recovery factory of the choices `T` for the list of parts `L`.
pub type RecoveryFactoryOf<T, L> = <T as Choices>::Recovery<LinkPathIdentifierOf<T, L>>;
/// The configuration the recovery factory is made from.
pub type RecoveryConfigOf<T, L> =
    <RecoveryFactoryOf<T, L> as RecoveryFactory<<T as ConnectionChoices>::Link>>::Config;
/// The RTT estimate of a link path.
pub type RttOf<T, L> =
    <RecoveryFactoryOf<T, L> as RecoveryFactory<<T as ConnectionChoices>::Link>>::Rtt;
/// The part of a link path's congestion control that its recovery layer
/// stores.
pub type CongestionPartOf<T, L> =
    <RecoveryFactoryOf<T, L> as RecoveryFactory<<T as ConnectionChoices>::Link>>::CongestionPart;
/// The datagram size probing policy of a link path.
pub type PmtuOf<T, L> =
    <RecoveryFactoryOf<T, L> as RecoveryFactory<<T as ConnectionChoices>::Link>>::Pmtu;
/// The other link paths as the recovery factory sees them when it lends.
pub type OthersOf<'s, T, L> =
    OtherCongestionParts<'s, PathKey<L>, LinkIdOf<T>, CongestionPartOf<T, L>>;
/// What the congestion controller lent for a link path keeps for each
/// packet in flight; the same for every lend.
pub type SentStateOf<T, L> =
    <RecoveryFactoryOf<T, L> as LendCongestion<InstantOf<T>, OthersOf<'static, T, L>>>::SentState;
/// What the congestion controller lent for a link path keeps for each batch
/// of losses; the same for every lend.
pub type LossStateOf<T, L> =
    <RecoveryFactoryOf<T, L> as LendCongestion<InstantOf<T>, OthersOf<'static, T, L>>>::LossState;

/// Where the recovery factory is among the connection's components.
#[derive(Debug)]
pub struct ChosenRecoveryFactory;
/// Where the RTT estimate is among a recovery layer's components.
#[derive(Debug)]
pub struct ChosenRttEstimator;
/// Where the stored part of congestion control is among a recovery
/// layer's components.
#[derive(Debug)]
pub struct ChosenCongestionPart;
/// Where the datagram size probing policy is among a recovery layer's
/// components.
#[derive(Debug)]
pub struct ChosenPmtuPolicy;
/// How the three parts the factory makes for a link path are built.
#[derive(Debug)]
pub struct ChosenRecoveryParts;

// ---- the factory, in the connection node ----

/// The factory is made from its configuration when the connection is.
impl<T, L, X, I> Build<T, L, layer::Connection, (ChosenRecoveryFactory, I)> for X
where
    T: Choices<Recovery<LinkPathIdentifierOf<T, L>> = X>,
    L: LineagePartList<T>,
    X: RecoveryFactory<T::Link>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        X::new(&own_args::<T, L, I>(args).recovery)
    }
}
impl<T, L, X> DataComponent<T, L, layer::Connection, ChosenRecoveryFactory> for X
where
    T: Choices<Recovery<LinkPathIdentifierOf<T, L>> = X>,
    L: LineagePartList<T>,
{
}

// ---- what the factory makes, in the recovery layer ----

/// The factory makes the three for the link path over the link in the
/// entry above, with the initial RTT the layer is built with.
impl<T, L, R, C, P, If, Il> Build<T, L, layer::Recovery, (ChosenRecoveryParts, If, Il)>
    for HList![R, C, P]
where
    T: Choices,
    L: LineagePartList<T>,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link, Rtt = R, CongestionPart = C, Pmtu = P>,
    for<'v> <L as LineageLists<'v, T>>::LinkPath:
        GetAt<RecoveryFactoryOf<T, L>, If> + GetAt<LinkClone<T::Link>, Il>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::Recovery>,
        args: &mut ArgsOf<T, L, layer::Recovery>,
    ) -> Self {
        // The clone is cloned again so that the factory can be changed while
        // the link is read; a recovery layer is built rarely.
        let link = parents.get::<LinkClone<T::Link>, Il>().0.clone();
        let (rtt, congestion, pmtu) = parents
            .get_mut::<RecoveryFactoryOf<T, L>, If>()
            .create(&link, args.initial_rtt);
        frunk_core::hlist![rtt, congestion, pmtu]
    }
}

/// The RTT estimate changes only with what the calls give it.
impl<T, L, X> DataComponent<T, L, layer::Recovery, ChosenRttEstimator> for X
where
    T: Choices,
    L: LineagePartList<T>,
    X: RttEstimator<InstantOf<T>>,
{
}

/// The probing policy's deadline is its own; it reads itself.
impl<T, L, X, I> DataComponent<T, L, layer::Recovery, (ChosenPmtuPolicy, I)> for X
where
    T: Choices,
    L: LineagePartList<T>,
    X: PmtuPolicy<T::Link> + 'static,
    for<'v> <L as LineageLists<'v, T>>::Recovery: GetAt<X, I>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add::<X>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Recovery>) -> Option<InstantOf<T>> {
        lineage.get::<X, I>().next_deadline()
    }
    fn expire<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Recovery>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        lineage.get_mut::<X, I>().on_deadline(now);
        None
    }
}

/// The stored part's deadline is the earliest of the lent access, which the
/// factory reads from the part: the next release of pacing among them.
/// When it comes, the pacer is refilled; what reads the part then sees the
/// new allowance. It reads itself.
impl<T, L, X, If, Ix, Iq, Ipp, It, Jx, Jr>
    DataComponent<T, L, layer::Recovery, (ChosenCongestionPart, If, Ix, (Iq, Ipp, It), (Jx, Jr))>
    for X
where
    T: Choices,
    L: LineagePartList<T>,
    L: ParametersOf<TransportParameterSpace>,
    X: 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link, CongestionPart = X>
        + for<'s> LendCongestion<InstantOf<T>, OthersOf<'s, T, L>, Part = X>,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, Ipp>,
    for<'v> <L as LineageLists<'v, T>>::Recovery: GetAt<RecoveryFactoryOf<T, L>, If>
        + GetAt<X, Ix>
        + ReadEach<LossFactsReads<T, L>, Iq>
        + TakeEach<'v, HList![RecoveryFactoryOf<T, L>, X], It>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a X, Jx> + Selector<&'a RttOf<T, L>, Jr>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add::<X>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Recovery>) -> Option<InstantOf<T>> {
        let factory = lineage.get::<RecoveryFactoryOf<T, L>, If>();
        factory.next_deadline(lineage.get::<X, Ix>())
    }
    fn expire<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, layer::Recovery>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let frunk_core::hlist_pat![_, rtt, pmtu, peer, link] =
            lineage.read_each::<LossFactsReads<T, L>, Iq>();
        let rtt = rtt.estimate();
        let size = max_datagram_size_in_use(
            pmtu.conclusion(),
            peer_max_udp_payload_size::<L, Ipp>(peer),
            link.0.max_datagram_size().ok(),
        );
        let (frunk_core::hlist_pat![factory, part], _) =
            Take::<HList![RecoveryFactoryOf<T, L>, X], It>::take(lineage);
        lend_congestion::<T, L, B, Jx, Jr, _>(factory, part, others, |mut access| {
            refill(&mut access, now, &rtt, size);
        });
        None
    }
}

/// The fixed state starts with nothing in flight.
impl<T: Choices, L> Build<T, L, layer::Recovery, ()> for LinkPathCongestionState<InstantOf<T>>
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
impl<I> PassiveDataComponent for LinkPathCongestionState<I> {}

// ---- lending ----

/// Lend this link path's congestion access, with the other link paths'
/// recovery layers read only, and use it.
///
/// `factory` and `part` are this link path's; the view is made from
/// `others` here, so that the one place that takes them is the same for
/// sending, an ACK and an expiry of the probe timeout.
pub fn lend_congestion<'s, T, L, B, Ix, Ir, O>(
    factory: &mut RecoveryFactoryOf<T, L>,
    part: &mut CongestionPartOf<T, L>,
    others: &'s OtherNodes<'_, T, L, B>,
    use_access: impl for<'a> FnOnce(
        <RecoveryFactoryOf<T, L> as LendCongestion<InstantOf<T>, OthersOf<'a, T, L>>>::Access<'a>,
    ) -> O,
) -> O
where
    T: Choices,
    L: crate::share::PartList<T>,
    B: CallBundle,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'a> LendCongestion<InstantOf<T>, OthersOf<'a, T, L>, Part = CongestionPartOf<T, L>>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Ix> + Selector<&'a RttOf<T, L>, Ir>,
{
    let layers = RecoveryLayers::<T, L, B, Ix, Ir> {
        others,
        positions: PhantomData,
    };
    let view = OtherCongestionParts { each: &layers };
    use_access(factory.lend(part, &view))
}

/// The other link paths' recovery layers, read only, as a recovery factory
/// sees them when it lends one link path's congestion access: for each, its
/// key, the part of its congestion control and its RTT estimate.
///
/// The link path whose access is lent is not among them, nor is a link path
/// without a recovery layer.
///
/// `K` is the key of a logical path, `Id` the identity of a link
/// ([`LinkIdOf`]), `P` the part.
pub struct OtherCongestionParts<'s, K, Id, P> {
    each: &'s dyn EachCongestionPart<K, Id, P>,
}

impl<K, Id, P> OtherCongestionParts<'_, K, Id, P> {
    /// Each of the other link paths with a recovery layer: the key of the
    /// layer, its part, its RTT estimate.
    pub fn each(&self, mut each: impl FnMut(&NodeKey<K, Id>, &P, RttEstimate)) {
        self.each.each(&mut each);
    }
}

impl<K, Id, P> fmt::Debug for OtherCongestionParts<'_, K, Id, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtherCongestionParts")
            .finish_non_exhaustive()
    }
}

/// What is called for each of the other recovery layers.
pub(crate) type EachPart<'f, K, Id, P> = dyn FnMut(&NodeKey<K, Id>, &P, RttEstimate) + 'f;

/// Going over the other recovery layers, whatever the calls of the tree
/// are.
pub(crate) trait EachCongestionPart<K, Id, P> {
    fn each(&self, each: &mut EachPart<'_, K, Id, P>);
}

/// The recovery layers reached from a lend, read by the positions of the
/// part and of the RTT estimate in a layer.
struct RecoveryLayers<
    's,
    'v,
    T: ConnectionChoices,
    L: crate::share::PartList<T>,
    B: CallBundle,
    Ix,
    Ir,
> {
    others: &'s OtherNodes<'v, T, L, B>,
    positions: PhantomData<fn() -> (Ix, Ir)>,
}

impl<T, L, B, Ix, Ir> EachCongestionPart<PathKey<L>, LinkIdOf<T>, CongestionPartOf<T, L>>
    for RecoveryLayers<'_, '_, T, L, B, Ix, Ir>
where
    T: Choices,
    L: crate::share::PartList<T>,
    B: CallBundle,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Ix> + Selector<&'a RttOf<T, L>, Ir>,
{
    fn each(&self, each: &mut EachPart<'_, PathKey<L>, LinkIdOf<T>, CongestionPartOf<T, L>>) {
        self.others.each_recovery(|key, data| {
            let flat = data.flat_ref();
            let part: &&CongestionPartOf<T, L> = Selector::<_, Ix>::get(&flat);
            let rtt: &&RttOf<T, L> = Selector::<_, Ir>::get(&flat);
            each(key, part, rtt.estimate());
        });
    }
}

// ---- the fixed state ----

/// What the protocol defines for a link path's congestion control, beside
/// the controller: the bytes in flight, the permits to send datagrams past
/// the window, whether sending is limited by the application, and the
/// arrival of the first RTT sample.
///
/// The controller is not in it; the methods take what the factory lends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPathCongestionState<I> {
    bytes_in_flight: usize,
    probe_permits: u8,
    app_limited: bool,
    first_rtt_sample_at: Option<I>,
}

impl<I> Default for LinkPathCongestionState<I> {
    fn default() -> Self {
        Self {
            bytes_in_flight: 0,
            probe_permits: 0,
            app_limited: false,
            first_rtt_sample_at: None,
        }
    }
}

impl<I: Copy> LinkPathCongestionState<I> {
    /// Nothing in flight, no permits, not limited by the application, no
    /// sample yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The bytes in flight.
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    /// `bytes` more are in flight. Probes count too (RFC 9002 §7.5), so the
    /// bytes in flight can go past the window.
    pub fn add_in_flight(&mut self, bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
    }

    /// `bytes` left the bytes in flight: acknowledged, declared lost, or
    /// removed without a signal.
    pub fn remove_in_flight(&mut self, bytes: usize) {
        debug_assert!(
            bytes <= self.bytes_in_flight,
            "only bytes that are in flight leave"
        );
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    /// How many datagrams may still be sent past the window.
    pub fn probe_permits(&self) -> u8 {
        self.probe_permits
    }

    /// `count` more datagrams may be sent past the window: at an expiry of
    /// the probe timeout, or when the controller asks to send before its
    /// window comes down (RFC 9002 §7.3.2).
    pub fn grant_probe_permits(&mut self, count: ProbeCount) {
        let count = u8::try_from(count.get()).unwrap_or(u8::MAX);
        self.probe_permits = self.probe_permits.saturating_add(count);
    }

    /// Use one permit for a datagram sent past the window; `false` when
    /// there is none.
    pub fn use_probe_permit(&mut self) -> bool {
        let Some(left) = self.probe_permits.checked_sub(1) else {
            return false;
        };
        self.probe_permits = left;
        true
    }

    /// No more datagrams past the window: an ACK newly acknowledged
    /// packets.
    pub fn clear_probe_permits(&mut self) {
        self.probe_permits = 0;
    }

    /// Whether sending is limited by the application (RFC 9002 §7.8).
    pub fn app_limited(&self) -> bool {
        self.app_limited
    }

    /// When the first RTT sample arrived, for persistent congestion.
    pub fn first_rtt_sample_at(&self) -> Option<I> {
        self.first_rtt_sample_at
    }

    /// The link path got an RTT sample from a datagram that arrived at
    /// `at`: the first one's arrival is kept.
    pub fn rtt_sampled(&mut self, at: I) {
        self.first_rtt_sample_at.get_or_insert(at);
    }

    /// What is left of the window: more is in flight than the window when
    /// probes went past it, and then nothing is left.
    pub fn window_left<C: CongestionController<I>>(&self, controller: &C) -> usize {
        controller.window().saturating_sub(self.bytes_in_flight)
    }

    /// The bytes pacing lets go at `now`, the instant of the poll: the
    /// pacer is refilled to `now` first.
    pub fn pacing_allowance<C: CongestionController<I> + Pacer<I>>(
        &self,
        controller: &mut C,
        now: I,
        rtt: &RttEstimate,
        max_datagram_size: usize,
    ) -> usize {
        refill(controller, now, rtt, max_datagram_size);
        controller.allowance()
    }

    /// A datagram ended with `in_flight` bytes that count in flight, and
    /// went past the window on a permit if it is a `probe`: the bytes go in
    /// flight, the permit is used, and pacing is charged, for probes too
    /// (RFC 9002 §7.5, §7.7).
    pub fn on_datagram_sealed<C: Pacer<I>>(
        &mut self,
        controller: &mut C,
        in_flight: usize,
        probe: bool,
    ) {
        self.add_in_flight(in_flight);
        if probe {
            let used = self.use_probe_permit();
            debug_assert!(
                used,
                "a probe goes past the window on a permit it was given"
            );
        }
        controller.on_charged(in_flight);
    }
}

/// Refill the pacer of a lent access to `at`.
pub(super) fn refill<I, C: CongestionController<I> + Pacer<I>>(
    controller: &mut C,
    at: I,
    rtt: &RttEstimate,
    max_datagram_size: usize,
) {
    let input = PacingInput {
        window: controller.window(),
        smoothed_rtt: rtt.smoothed,
        max_datagram_size,
    };
    controller.refill(at, input);
}

/// The maximum datagram size a link path uses: the smallest of what its
/// probing policy concluded, the peer's `max_udp_payload_size` once its
/// transport parameters are known, and the link's limit raised to 1200
/// (RFC 9000 §14). A link whose limit cannot be told gives 1200 only.
pub fn max_datagram_size_in_use(
    conclusion: usize,
    peer_limit: Option<usize>,
    link_limit: Option<usize>,
) -> usize {
    let link = link_limit.unwrap_or(0).max(MIN_DATAGRAM_SIZE);
    conclusion
        .min(peer_limit.unwrap_or(usize::MAX))
        .min(link)
        .max(MIN_DATAGRAM_SIZE)
}

/// The peer's `max_udp_payload_size`: its default 65527 when the peer left
/// it out (RFC 9000 §18.2), nothing while its transport parameters are not
/// known.
pub(super) fn peer_max_udp_payload_size<L, I>(
    peer: &PeerTransportParameters<TransportParameterSlots<L>>,
) -> Option<usize>
where
    L: ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, I>,
{
    const DEFAULT: u64 = 65527;
    let slots = peer.known()?;
    let value = slots
        .get()
        .as_ref()
        .map_or(DEFAULT, |size: &MaxUdpPayloadSize| u64::from(size.get()));
    Some(usize::try_from(value).unwrap_or(usize::MAX))
}
