//! The send strategy in the connection's tree: its core in the connection
//! node, a send planner in the node of each link path, and what each is
//! told when the components it follows change.
//!
//! Whoever changes a key, the handshake's confirmation, the record of why
//! the connection closed or a link path's role only changes its own
//! component; the core and the planners read those components, and the
//! driver rereads them after a lend that changed one. Each remembers what
//! it told the strategy last, so the same fact is told once.

use core::{fmt, task::Waker};
use std::sync::Arc;

use sakuya_link::Link;
use sakuya_packet_protection::{backend::AEAD_TAG_LEN, packet_number::TruncatedPacketNumber};
use sakuya_wire::{
    header::SAMPLE_DISTANCE,
    parameters::ParametersOf,
    parts::{CoprodInjector, Selector},
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
    congestion::CongestionController,
    pacing::Pacer,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pmtu::PmtuPolicy,
    receive_journals::ReceiveJournals,
    send_journals::SendJournals,
};

use sakuya_stream::{connection::CloseReason, send_options::destination::Unfulfilled};

use super::{
    AckObligationsOf, Choices, CloseCauseOf, Side,
    amplification::AntiAmplification,
    close::{CloseReasonRecord, LocalCloseCause},
    close_packet::ClosePacket,
    confirmation::HandshakeConfirmation,
    connection_ids::{ConnectionIdsOf, ResetTokenRegistrarOf},
    crypto::send::CryptoSender,
    error::{ConnectionError, V1ConnectionErrorOf},
    feedback::LineageFeedback,
    keys::{HandshakeKeys, InitialKeys, OneRttKeys},
    link::{LinkClone, LinkFacts},
    parameters::PeerTransportParameters,
    path_response::PendingPathResponse,
    pmtu_probe::PendingPmtuProbe,
    receive::v1_error,
    recovery::{CongestionPartOf, LinkPathCongestionState, PmtuOf, peer_max_udp_payload_size},
    send::{PendingProbePings, SendTypes},
    spaces::SendJournalsOf,
};
use crate::role::LinkPathRole;
use crate::v1::{CryptoSendBufferOf, HostChoices, HostOf};
use crate::{
    call::CallBundle,
    clock::{InstantOf, LinkIdOf},
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, ReadSet,
        RequestOf,
    },
    connection_id::DestinationConnectionIdStrategy,
    error::ConnectionErrorsOf,
    feedback::FeedbackSummariesOf,
    frame_source::{
        DriverContentOf, EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts,
    },
    layer::{self, NodeKey},
    others::OtherNodes,
    send_strategy::{
        DatagramLimits, DriverContent, FrameSourceSet, LinkPathRoleKind, LinkPathSendPlanner,
        Observe, PacketOverheads, PlannedPacketKind, PublishOutcome, SendIntent, SendIntentsOf,
        SendStrategy, SendStrategyTypes,
    },
    share::{FlatMut, FlatRef, LineageLists, LineagePartList, LogicalPathKeys, NodeData},
    take::{GetAt, ReadEach, Take, TakeEach},
    write::FlightClass,
};

/// The core of the send strategy of the choices `T` and the list of parts
/// `L`.
pub type SendStrategyOf<T, L> = <SendTypes<T, L> as HostSendStrategyTypes>::Strategy;

/// Send strategy types that the send strategy of the host's choices runs
/// on: [`SendTypes<T, L>`] once the strategy of `T`'s host is a
/// [`SendStrategy`] over them. One bound stands for both, where each would
/// otherwise be stated.
pub trait HostSendStrategyTypes: SendStrategyTypes + Sized {
    /// The send strategy of the host's choices over these types.
    type Strategy: SendStrategy<Self> + Default;
}

impl<T: Choices, L> HostSendStrategyTypes for SendTypes<T, L>
where
    Self: SendStrategyTypes,
    <HostOf<T> as HostChoices<T>>::SendStrategy<Self>: SendStrategy<Self>,
{
    type Strategy = <HostOf<T> as HostChoices<T>>::SendStrategy<Self>;
}

/// The send planner of one link path, as the core of `T` and `L` makes it.
pub type LinkPathSendPlannerOf<T, L> =
    <SendStrategyOf<T, L> as SendStrategy<SendTypes<T, L>>>::LinkPathSendPlanner;

/// The intake of the send strategy of the choices `T` and the list of
/// parts `L`.
pub type IntakeOf<T, L> = <SendStrategyOf<T, L> as SendStrategy<SendTypes<T, L>>>::Intake;

/// `SendTypes<T, L>: IntakePublishOutcome<J, D>`: the intake of the core of
/// the choices `T` and the list of parts `L` takes intents `J` for the
/// destination `D` and gives back [`Outcome`](Self::Outcome). A component
/// that keeps what it gets back names its type by this, without the place
/// of `J`.
pub trait IntakePublishOutcome<J: SendIntent, D>: SendStrategyTypes {
    /// What publishing gives back.
    type Outcome;
}

impl<T, L, J, D> IntakePublishOutcome<J, D> for SendTypes<T, L>
where
    T: Choices,
    J: SendIntent,
    Self: HostSendStrategyTypes,
    IntakeOf<T, L>: PublishOutcome<J, D>,
{
    type Outcome = <IntakeOf<T, L> as PublishOutcome<J, D>>::Outcome;
}

/// The intake of the send strategy (`SendStrategyIntake`), in the
/// connection node: a clone of what the core gives out, made with the core,
/// so that what publishes while the core is lent elsewhere, such as the
/// frame sources of the streams while a sending call has the core to fill
/// its packets, finds it in its lineage and takes its handle there.
pub struct SendStrategyIntake<X>(X);

impl<X> fmt::Debug for SendStrategyIntake<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendStrategyIntake").finish_non_exhaustive()
    }
}

impl<X> SendStrategyIntake<X> {
    /// The intake.
    pub fn intake(&self) -> &X {
        &self.0
    }
}

/// The core and its intake are made together: the core as the choices'
/// strategy makes it by default, the intake the one it gives out.
impl<T: Choices, L> Build<T, L, layer::Connection, ()>
    for frunk_core::HList![
        SendStrategyCore<SendStrategyOf<T, L>>,
        SendStrategyIntake<IntakeOf<T, L>>
    ]
where
    L: LineagePartList<T>,
    SendTypes<T, L>: HostSendStrategyTypes,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let core = SendStrategyCore::new(SendStrategyOf::<T, L>::default());
        let intake = SendStrategyIntake(core.strategy().intake());
        frunk_core::hlist![core, intake]
    }
}

/// It has no deadline and reads nothing: it only hands out handles.
impl<X> PassiveDataComponent for SendStrategyIntake<X> {}

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

    /// The core, to plan with.
    pub fn strategy_mut(&mut self) -> &mut S {
        &mut self.strategy
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
    SendTypes<T, L>: HostSendStrategyTypes,
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
        let mut core = lineage.get_mut::<Self, I>();
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

/// The send planner of the link paths of the choices `T` and the list of
/// parts `L`, as the link path's node holds it.
pub type LinkPathPlannerOf<T, L> = LinkPathPlanner<
    LinkPathSendPlannerOf<T, L>,
    <SendTypes<T, L> as SendStrategyTypes>::SendIntents,
>;

/// The send planner of a link path, in the link path's node, with the
/// role, the limits and the packet overheads it was last told, how the
/// sending call waits after a plan it could not fill, and what the driver's
/// own components have to send, of the sum of intents `J`: gathered for
/// each plan, and as the sending call last saw it.
pub struct LinkPathPlanner<P, J> {
    planner: P,
    role: LinkPathRoleKind,
    limits: Option<DatagramLimits>,
    overheads: Option<PacketOverheads>,
    blocked: BlockedFilling,
    /// What the driver's components have to send, as last gathered; kept
    /// for its room only.
    driver: DriverContent<J>,
    /// What the sending call last saw of the driver's content: what it
    /// planned with last, or was woken for.
    seen: DriverContent<J>,
    /// The waker of the sending call, kept when its filling ended because
    /// the planner had nothing to plan or the plan could not be filled.
    waker: Option<Waker>,
}

/// Where the sending call of a link path stands after plans it could not
/// fill: content of a level without keys to send with, or that no
/// connection ID offered fits.
///
/// A planner that plans such content keeps no waker. The call wakes itself
/// once, so that the planner, told what the lend changed, plans again;
/// blocked again while nothing it is told has changed, the call waits
/// until something does.
#[derive(Debug, Default)]
enum BlockedFilling {
    /// The last filling was not blocked, or the planner was told something
    /// new since.
    #[default]
    No,
    /// The last filling was blocked and the call woke itself.
    WokeItself,
    /// Blocked again: the call waits with this waker for what the planner
    /// is told to change.
    Waiting(Waker),
}

impl<P, J> fmt::Debug for LinkPathPlanner<P, J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkPathPlanner")
            .field("role", &self.role)
            .field("limits", &self.limits)
            .field("overheads", &self.overheads)
            .field("blocked", &self.blocked)
            .field("seen", &self.seen.intents.len())
            .finish_non_exhaustive()
    }
}

impl<P, J> LinkPathPlanner<P, J> {
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

    /// The planner, to tell of its send conditions or to plan with.
    pub fn planner_mut(&mut self) -> &mut P {
        &mut self.planner
    }

    /// The planner, to plan with, and the driver's content, cleared, for
    /// the sending call to gather what the driver's components have to send
    /// into before it asks for a plan.
    pub(super) fn planner_and_driver_content(&mut self) -> (&mut P, &mut DriverContent<J>) {
        self.driver.clear();
        (&mut self.planner, &mut self.driver)
    }

    /// A filling of the link path ended, `blocked` when by a plan it could
    /// not fill and with nothing to hand over, `waits` when it waits for
    /// content: the planner had nothing to plan, or the plan could not be
    /// filled. The driver's content last gathered is what the sending call
    /// saw; when it waits, its `waker` is kept, to wake it once that
    /// content changes. Returns whether the sending call wakes itself to
    /// plan again: the first time it is blocked; after that it waits with
    /// `waker` until the planner is told something new.
    pub(super) fn filling_ended(&mut self, blocked: bool, waits: bool, waker: &Waker) -> bool {
        core::mem::swap(&mut self.driver, &mut self.seen);
        if waits {
            self.waker = Some(waker.clone());
        }
        if !blocked {
            self.blocked = BlockedFilling::No;
            return false;
        }
        match self.blocked {
            BlockedFilling::No => {
                self.blocked = BlockedFilling::WokeItself;
                true
            }
            BlockedFilling::WokeItself | BlockedFilling::Waiting(_) => {
                self.blocked = BlockedFilling::Waiting(waker.clone());
                false
            }
        }
    }

    /// The planner was told something new: a sending call waiting after a
    /// blocked filling plans again.
    fn told_anew(&mut self) {
        if let BlockedFilling::Waiting(waker) = core::mem::take(&mut self.blocked) {
            waker.wake();
        }
    }

    /// What the driver's components have to send changed from what the
    /// sending call saw, to `content`, in a way the call may send: it is
    /// woken, and `content` is what it saw.
    fn wake_for(&mut self, content: DriverContent<J>) {
        self.seen = content;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// The kinds of packet a link path in `role` sends, as the send strategy
/// sees them: the content of a role goes in packets of these kinds only.
fn kinds_of(role: LinkPathRoleKind) -> &'static [PlannedPacketKind] {
    match role {
        LinkPathRoleKind::Active => &[
            PlannedPacketKind::Initial,
            PlannedPacketKind::Handshake,
            PlannedPacketKind::OneRtt,
            PlannedPacketKind::ZeroRtt,
        ],
        LinkPathRoleKind::Candidate => &[PlannedPacketKind::OneRttProbe],
        LinkPathRoleKind::Settling => &[PlannedPacketKind::SettlingResponse],
        LinkPathRoleKind::Closing | LinkPathRoleKind::Draining => &[],
    }
}

/// Whether a packet of `kind` can carry `intent`.
fn carries<I: SendStrategyTypes>(kind: PlannedPacketKind, intent: &I::SendIntents) -> bool {
    match kind {
        PlannedPacketKind::Initial => I::InitialFrameSources::item(intent).is_some(),
        PlannedPacketKind::Handshake => I::HandshakeFrameSources::item(intent).is_some(),
        PlannedPacketKind::ZeroRtt => I::ZeroRttFrameSources::item(intent).is_some(),
        PlannedPacketKind::OneRtt => I::OneRttFrameSources::item(intent).is_some(),
        PlannedPacketKind::OneRttProbe => I::ProbeFrameSources::item(intent).is_some(),
        PlannedPacketKind::SettlingResponse => I::SettlingFrameSources::item(intent).is_some(),
    }
}

/// Whether `intent`, by the least room it gives, fits an empty datagram of
/// a link path in `role` that can send `limits`, with `overheads`: in the
/// first kind of packet of the role that can carry it and that the link
/// path can send now. Content that counts in flight in an Initial packet,
/// and any in a client's, fills a datagram of 1200 bytes (RFC 9000 §14.1).
fn fits_empty_datagram<I: SendStrategyTypes>(
    intent: &I::SendIntents,
    role: LinkPathRoleKind,
    limits: &DatagramLimits,
    overheads: &PacketOverheads,
) -> bool {
    let Some((kind, overhead)) = kinds_of(role)
        .iter()
        .filter(|&&kind| carries::<I>(kind, intent))
        .find_map(|&kind| overheads.of(kind).map(|overhead| (kind, overhead)))
    else {
        return false;
    };
    let class = I::flight_class(intent);
    let mut class_of_datagram = class;
    let mut need = overhead + I::min_lengths(intent).as_last;
    if kind == PlannedPacketKind::Initial
        && (overheads.expands_every_initial || class == FlightClass::InFlight)
    {
        need = need.max(DatagramLimits::MINIMUM);
        class_of_datagram = FlightClass::InFlight;
    }
    need <= limits.capacity_for(class_of_datagram)
}

/// Whether two intents are the same content to the sending call: of the
/// same frame source, needing the same least room.
fn same_content<I: SendStrategyTypes>(a: &I::SendIntents, b: &I::SendIntents) -> bool
where
    I::FrameSourceId: PartialEq,
{
    I::frame_source(a) == I::frame_source(b) && I::min_lengths(a) == I::min_lengths(b)
}

/// Whether the driver's content `now` wakes a sending call that saw `seen`:
/// the facts of the close packet changed, or one of the intents, by its
/// frame source and least room, is not among those seen and fits an empty
/// datagram of the link path.
fn driver_content_wakes<I: SendStrategyTypes>(
    now: &DriverContent<I::SendIntents>,
    seen: &DriverContent<I::SendIntents>,
    role: LinkPathRoleKind,
    limits: &DatagramLimits,
    overheads: &PacketOverheads,
) -> bool
where
    I::FrameSourceId: PartialEq,
{
    now.close != seen.close
        || now.intents.iter().any(|intent| {
            !seen
                .intents
                .iter()
                .any(|seen| same_content::<I>(intent, seen))
                && fits_empty_datagram::<I>(intent, role, limits, overheads)
        })
}

/// A link path's planner is made by the core when the link path is built,
/// in the role its request gives it, and handed back to the core when the
/// link path ends; the intents the planner ends then go back to their frame
/// sources as not fulfilled, in the parents with the components of the
/// established layer the frame sources find appended.
///
/// `Ic` is the place of the core among the parents, `Hf` that of each
/// part's frame sources for handing intents back, and `Is` of
/// the established layer's components the frame sources find.
impl<T: Choices, L, Ic, Hf, Is> Build<T, L, layer::LinkPath, (Ic, Hf, Is)>
    for LinkPathPlannerOf<T, L>
where
    L: LineagePartList<T> + LogicalPathKeys + FeedbackSummariesOf,
    SendTypes<T, L>:
        SendStrategyTypes<LinkPathIdentifier = crate::share::LinkPathIdentifierOf<T, L>>,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'v> <L as LineageLists<'v, T>>::LinkPathParents: GetAt<SendStrategyCore<SendStrategyOf<T, L>>, Ic>
        + LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    L: EstablishedSourceComponentsOf<T, L>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Is>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        args: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        let role = args.role.kind();
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
            blocked: BlockedFilling::No,
            driver: DriverContent::new(),
            seen: DriverContent::new(),
            waker: None,
        }
    }

    fn end<'v, B: CallBundle>(
        self,
        parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
    ) {
        let mut ended = Vec::new();
        self.planner.ended(
            parents
                .get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Ic>()
                .strategy_mut(),
            &mut ended,
        );
        if ended.is_empty() {
            return;
        }
        let now = others.now();
        let mut established =
            others.borrow_established_optional::<EstablishedSourceComponentsOfParts<T, L>, Is>();
        LineageFeedback::<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>::unfulfilled_each(
            parents,
            &mut established,
            now,
            ended,
            Unfulfilled::Ended,
        );
    }
}

/// A planner is told when its link path's role changes; what the link
/// path can send whenever a component that limits it changes: the logical
/// link's clone, taken when the link's datagram size limit may have
/// changed, and its facts, the anti-amplification credit, the peer's
/// transport parameters, and the congestion control, its fixed state and
/// the datagram size probing policy in the link path's recovery layer; and
/// what each kind of packet takes beyond its frames whenever a component it
/// follows from changes: the connection IDs, the packet number states and
/// send journals of the spaces, and the keys of each level. All of it is
/// only read here.
///
/// Before it gathers the driver's content, it copies the datagram size probe
/// to send ([`PendingPmtuProbe`]) from the probing policy, which it reads:
/// the policy's probe on an `Active` link path once the handshake, which it
/// reads too, is confirmed, unless a probe of that size awaits its result
/// in the fixed congestion state. It changes the component only when the
/// probe to send changes.
///
/// It also reads what the driver's own components have to send on the link
/// path ([`DriverContentOf`]): the ACK obligations and receive journals,
/// the CRYPTO output, the data only this side has, which holds a server's
/// HANDSHAKE_DONE, the connection IDs, the probe's PINGs, the response to a
/// PATH_CHALLENGE, the datagram size probe and the close packet. When that content has an intent the
/// sending call did not see last, by its frame source and least room, that
/// fits an empty datagram as the link path can send now, or the close
/// packet's facts changed, the sending call is woken; content that does not
/// fit wakes it once the link path's conditions change so that it does, and
/// content gone since is forgotten as seen.
///
/// An `Active` link path that does not carry 1200 bytes stops sending
/// (RFC 9000 §14.2); when no other link path of the connection can send,
/// that is, none is `Active` and carries 1200 bytes, as its planner was
/// last told, and none is a candidate still being validated, the
/// connection closes with NO_VIABLE_PATH: the record of why it closed
/// takes the error, unless a reason is there already.
///
/// The intents the planner ends when its role changes go back to their
/// frame sources as not fulfilled, in the rest of the lineage with the
/// components of the established layer the frame sources find appended:
/// `Ik` is the place of the core there, `Hf` that of each part's frame
/// sources for handing intents back, and `Is` of the
/// established layer's components; `Hd` holds the positions each part reads
/// its content by.
impl<T: Choices, L, Ip, Ir, It, Il, Io, Ipp, Jc, Js, Jm, Ic, Ier, Kr, Kp, Ik, Hf, Is, Hd, Ipm, Ihc>
    DataComponent<
        T,
        L,
        layer::LinkPath,
        (
            Ip,
            Ir,
            It,
            Il,
            Io,
            Ipp,
            (Jc, Js, Jm),
            (Ic, Ier, Kr, Kp),
            (Ik, Hf, Is),
            Hd,
            (Ipm, Ihc),
        ),
    > for LinkPathPlannerOf<T, L>
where
    L: LineagePartList<T> + FeedbackSummariesOf + ParametersOf<TransportParameterSpace>,
    L: ConnectionErrorsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ier>,
    <SendTypes<T, L> as SendStrategyTypes>::SendIntents: From<<L as SendIntentsOf>::SendIntents>,
    <SendTypes<T, L> as SendStrategyTypes>::FrameSourceId: PartialEq,
    for<'v> L: DriverContentOf<T, L, <L as LineageLists<'v, T>>::LinkPath, Hd>,
    SendTypes<T, L>: HostSendStrategyTypes,
    LinkPathSendPlannerOf<T, L>: Observe<DatagramLimits> + Observe<PacketOverheads>,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, Ipp>,
    CongestionPartOf<T, L>: CongestionController<InstantOf<T>> + Pacer<InstantOf<T>>,
    for<'v> <L as LineageLists<'v, T>>::LinkPath: GetAt<Self, Ip>
        + GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + ReadEach<DatagramLimitsReads<T, L>, Il>
        + ReadEach<PacketOverheadsReads<T, L>, Io>
        + TakeEach<'v, frunk_core::HList![Self], It>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<PendingPmtuProbe, Ipm>
        + GetAt<HandshakeConfirmation, Ihc>,
    for<'v> <<L as LineageLists<'v, T>>::LinkPath as TakeEach<'v, frunk_core::HList![Self], It>>::Rest:
        GetAt<SendStrategyCore<SendStrategyOf<T, L>>, Ik>
            + LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    L: EstablishedSourceComponentsOf<T, L>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Is>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out: Selector<&'a CongestionPartOf<T, L>, Jc>
        + Selector<&'a LinkPathCongestionState<InstantOf<T>>, Js>
        + Selector<&'a PmtuOf<T, L>, Jm>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Kr> + GetAt<Self, Kp>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add::<LinkPathRole<InstantOf<T>>>();
        reads.add::<LinkClone<T::Link>>();
        reads.add::<LinkFacts>();
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
        // what the driver's content is read from
        reads.add::<AckObligationsOf<T>>();
        reads.add::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>>();
        reads.add::<CryptoSender<CryptoSendBufferOf<T>>>();
        reads.add::<<T::Side as Side>::Own>();
        reads.add::<PendingProbePings>();
        reads.add::<PendingPathResponse>();
        reads.add::<ClosePacket>();
        // what the datagram size probe to send is copied from
        reads.add::<HandshakeConfirmation>();
        reads.add::<PendingPmtuProbe>();
    }

    fn reread<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let role = lineage.get::<LinkPathRole<InstantOf<T>>, Ir>().kind();
        let limits = read_datagram_limits::<T, L, B, Il, Ipp, Jc, Js, Jm>(&lineage, others);
        if role == LinkPathRoleKind::Active
            && !limits.supports_minimum()
            && !lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .is_written()
            && !another_can_send::<T, L, B, Kr, Kp>(others)
        {
            let error = v1_error::<L, Ier>(ConnectionError::NoViablePath);
            lineage
                .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .record(CloseReason::Local(Arc::new(LocalCloseCause::Connection(
                    error,
                ))));
        }
        let NodeKey::LinkPath(path, link) = others.here() else {
            unreachable!("a link path's lend carries its key")
        };
        let identifier = L::link_path_identifier(path, link);
        // the datagram size probe to send, copied from the probing policy
        // after its events
        let confirmation = *lineage.get::<HandshakeConfirmation, Ihc>();
        let wanted = others.recovery_ref().and_then(|flat| {
            let state: &&LinkPathCongestionState<InstantOf<T>> = Selector::<_, Js>::get(&flat);
            let pmtu: &&PmtuOf<T, L> = Selector::<_, Jm>::get(&flat);
            PendingPmtuProbe::wanted(
                role,
                confirmation,
                || pmtu.probe_size(),
                state.pmtu_probe_awaited(),
            )
        });
        if lineage.get::<PendingPmtuProbe, Ipm>().size() != wanted {
            lineage.get_mut::<PendingPmtuProbe, Ipm>().set(wanted);
        }
        let overheads = read_packet_overheads::<T, L, Io>(
            &lineage,
            link,
            limits.capacity_for(FlightClass::AckOnly),
        );
        // what the driver's components have to send, gathered with the
        // room of the last gathering
        let mut content = core::mem::take(&mut lineage.get_mut::<Self, Ip>().driver);
        content.clear();
        <L as DriverContentOf<T, L, _, Hd>>::pending(
            &lineage,
            &identifier,
            &mut content,
            From::from,
        );
        let mut told = lineage.get_mut::<Self, Ip>();
        if driver_content_wakes::<SendTypes<T, L>>(&content, &told.seen, role, &limits, &overheads)
        {
            told.wake_for(content);
        } else {
            // what is gone was seen to go; what did not fit is not seen,
            // so that it wakes the call once it fits
            told.seen.intents.retain(|seen| {
                content
                    .intents
                    .iter()
                    .any(|now| same_content::<SendTypes<T, L>>(seen, now))
            });
            told.driver = content;
        }
        let told = lineage.get::<Self, Ip>();
        if told.role == role && told.limits == Some(limits) && told.overheads == Some(overheads) {
            return None;
        }
        let (frunk_core::hlist_pat![mut planner], mut rest) =
            Take::<frunk_core::HList![Self], It>::take(lineage);
        if planner.role != role {
            planner.role = role;
            let mut ended = Vec::new();
            planner.planner.role_changed(
                rest.get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Ik>()
                    .strategy_mut(),
                role,
                &mut ended,
            );
            if !ended.is_empty() {
                let mut established = others
                    .borrow_established_optional::<EstablishedSourceComponentsOfParts<T, L>, Is>();
                LineageFeedback::<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>::unfulfilled_each(
                    &mut rest,
                    &mut established,
                    now,
                    ended,
                    Unfulfilled::Ended,
                );
            }
        }
        if planner.limits != Some(limits) {
            planner.limits = Some(limits);
            planner.planner.observe(limits);
        }
        if planner.overheads != Some(overheads) {
            planner.overheads = Some(overheads);
            planner.planner.observe(overheads);
        }
        planner.told_anew();
        None
    }
}

/// Whether a link path other than the lent one can send: one `Active` that
/// carries 1200 bytes, as its planner was last told, or a candidate still
/// being validated.
fn another_can_send<'v, T, L, B, Kr, Kp>(others: &mut OtherNodes<'v, T, L, B>) -> bool
where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Kr> + GetAt<LinkPathPlannerOf<T, L>, Kp>,
{
    let mut roles = Vec::new();
    others.each_link_path_read::<LinkPathRole<InstantOf<T>>, Kr>(|key, role| {
        roles.push((key.clone(), role.kind()));
    });
    let mut can = false;
    others.each_link_path_read::<LinkPathPlannerOf<T, L>, Kp>(|key, planner| {
        let Some((_, role)) = roles.iter().find(|(each, _)| each == key) else {
            return;
        };
        can |= match role {
            LinkPathRoleKind::Candidate => true,
            LinkPathRoleKind::Active => planner
                .limits
                .is_some_and(|limits| limits.supports_minimum()),
            _ => false,
        };
    });
    can
}

// ---- what a link path can send ----

/// What a link path's recovery layer says about what it can send: what the
/// congestion window leaves, what pacing releases and how many datagrams
/// may go past both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CongestionAllowance {
    pub(super) window_left: usize,
    pub(super) pacing_allowance: usize,
    pub(super) pacing_release_pending: bool,
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
            pacing_release_pending: false,
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
        pacing_release_pending: congestion.pacing_release_pending,
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
                pacing_release_pending: Pacer::next_release(*controller).is_some(),
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
/// spaces, the keys of each level, and the data only this side has, which
/// gives the token of its Initial packets.
pub(super) type PacketOverheadsReads<T, L> = frunk_core::HList![
    ConnectionIdsOf<T>,
    PacketNumberSpaces<PacketNumberSpaceState>,
    SendJournalsOf<T, L>,
    InitialKeys<<T as crate::v1::MakerChoices>::Crypto>,
    HandshakeKeys<<T as crate::v1::MakerChoices>::Crypto>,
    OneRttKeys<<T as crate::v1::MakerChoices>::Crypto, InstantOf<T>>,
    <<T as crate::v1::MakerChoices>::Side as Side>::Own,
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
/// `journals` and `numbers` give them, the length `initial_token_len` of
/// the token of this side's Initial packets, and `max_len`, the largest
/// datagram the link path can send now.
#[allow(clippy::too_many_arguments)] // each is a separate fact read elsewhere
pub(super) fn link_path_packet_overheads<T, L>(
    ids: &ConnectionIdsOf<T>,
    link: &LinkIdOf<T>,
    numbers: &PacketNumberSpaces<PacketNumberSpaceState>,
    journals: &SendJournalsOf<T, L>,
    keys: SendKeyLevels,
    initial_token_len: usize,
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
        initial_token_len,
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
    let frunk_core::hlist_pat![ids, numbers, journals, initial, handshake, one_rtt, own] =
        lineage.read_each::<PacketOverheadsReads<T, L>, Io>();
    let keys = SendKeyLevels {
        initial: initial.send().is_some(),
        handshake: handshake.send().is_some(),
        one_rtt: one_rtt.send().is_some(),
    };
    let initial_token_len = <T::Side as Side>::initial_token(own).len();
    link_path_packet_overheads::<T, L>(
        ids,
        link,
        numbers,
        journals,
        keys,
        initial_token_len,
        max_len,
    )
    .1
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
/// connection ID a long header carries; `initial_token_len` the length of
/// the token an Initial packet of this side carries, always 0 for a server
/// (RFC 9000 §17.2.2). `max_len` is the largest datagram
/// the link path can send now: the packet writer reserves a long header's
/// Length field wide enough for it. `initial`, `handshake` and `one_rtt`
/// are the next packet numbers of the spaces whose levels have keys to
/// send with, `None` for one that has none; a 0-RTT packet is never
/// planned, as no 0-RTT keys to send with are kept.
#[allow(clippy::too_many_arguments)] // each is a separate fact of the packets
pub(super) fn packet_overheads(
    dcid_len: Option<usize>,
    scid_len: usize,
    initial_token_len: usize,
    max_len: usize,
    initial: Option<NextPacketNumber>,
    handshake: Option<NextPacketNumber>,
    one_rtt: Option<NextPacketNumber>,
    role: Role,
) -> PacketOverheads {
    let length_width =
        VarIntWidth::shortest(VarInt::try_from(max_len).unwrap_or(VarInt::MAX)).encoded_len();
    let initial_token =
        VarIntWidth::shortest(VarInt::try_from(initial_token_len).unwrap_or(VarInt::MAX))
            .encoded_len()
            + initial_token_len;
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
        initial: long(dcid_len, initial, initial_token),
        handshake: long(dcid_len, handshake, 0),
        zero_rtt: None,
        one_rtt: one_rtt
            .and_then(NextPacketNumber::encoded_len)
            .map(|pn_len| 1 + dcid_len + numbered(pn_len) + AEAD_TAG_LEN),
        expands_every_initial: role == Role::Client,
    }
}

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
            0,
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
            0,
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
    fn a_clients_initial_takes_its_token_with_the_tokens_length() {
        let overheads = packet_overheads(
            Some(8),
            8,
            100,
            1200,
            next(0, None),
            None,
            None,
            Role::Client,
        );
        // a token of 100 bytes and its length of two bytes, where an empty
        // one takes one byte of length
        assert_eq!(
            overheads.initial,
            Some(1 + 4 + 1 + 8 + 1 + 8 + 2 + 100 + 2 + 1 + 3 + 16)
        );
    }

    #[test]
    fn the_header_protection_sample_takes_what_the_packet_number_leaves_of_four_bytes() {
        // a zero-length connection ID: the first byte, a packet number of
        // one byte, which leaves three bytes of the four to the payload
        // (RFC 9001 §5.4.2), and the tag; a packet number of four bytes
        // leaves none
        let short = packet_overheads(Some(0), 0, 0, 1200, None, None, next(0, None), Role::Server);
        assert_eq!(short.one_rtt, Some(1 + 1 + 3 + 16));
        let long = packet_overheads(
            Some(0),
            0,
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
            0,
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
