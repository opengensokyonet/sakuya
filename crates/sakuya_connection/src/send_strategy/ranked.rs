//! A send strategy that ranks content: acknowledgments first, then path
//! validation, the handshake, control frames, path MTU probes and
//! application data, and within a rank by encryption level.
//!
//! Content that does not fit holds its place: nothing ranked after it goes
//! into the datagram, so it is not starved by what comes later, unless it
//! does not hold its place (a path MTU probe, or content waiting for a
//! larger datagram size). Content whose kind of packet the link path
//! cannot send at all now, as its keys are gone or no connection ID is
//! offered, is passed over: it holds no place and leaves no threshold, as
//! no room would let it go. A datagram's packets go in increasing encryption
//! level: content of a lower level than what is already planned yields, and
//! with it everything after it, to the next datagram.
//!
//! The core holds the intents the driver's components publish for any
//! active link path; each link path's planner holds the intents bound to
//! it. A planner with nothing to plan keeps, for each flight class, the
//! least room blocked content needs, and is woken when its observed
//! conditions reach it, when content is published, or when the keys or its
//! role change.
//!
//! A closing link path sends its close packet again ([`ResendCloseIntent`])
//! when it is sealed, and then for the first, second, fourth, eighth and
//! every further power of two among the datagrams it receives while it
//! closes: the rate falls as the peer keeps sending (RFC 9000 §10.2.1).
//! What was published before its planner was told of the closing role
//! waits for it; a draining link path sends nothing.

use core::{
    fmt,
    marker::PhantomData,
    sync::atomic::{AtomicU8, Ordering},
    task::{Context, Poll, Waker},
};
use std::sync::{Arc, OnceLock};

use sakuya_stream::connection::{CloseReason, ConnectionClosedError};
use sakuya_wire::{
    parts::{CNil, Coproduct},
    v1::encryption_level::EncryptionLevel,
};

use super::{
    AnyActiveLinkPath, DatagramFillPlan, DatagramLimits, FrameSourceCursor, FrameSourceSet,
    InjectSendIntent, IntentRejected, IntentState, LeadingContent, LinkPathPublishError,
    LinkPathRoleKind, LinkPathSendPlanner, MinimumLengths, Observe, PacketOverheads,
    PlannedDatagram, PlannedItem, PlannedPacket, PlannedPacketKind, PlannerLinkPath, Publish,
    PublishOutcome, PublishTo, ResendCloseIntent, RoleNotAcceptingError, SendIntent, SendStrategy,
    SendStrategyTypes, SupplyFeedback,
};
use crate::write::FlightClass;

// ---- ranks ----

/// The ranks of content, first to last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SendPriority {
    /// ACK frames.
    Acknowledgment,
    /// PATH_CHALLENGE and PATH_RESPONSE frames.
    PathValidation,
    /// CRYPTO and HANDSHAKE_DONE frames.
    Handshake,
    /// Flow control updates and other control frames.
    Control,
    /// Path MTU probes.
    PathMtuProbe,
    /// STREAM and DATAGRAM frames.
    ApplicationData,
}

/// Where content ranks, and whether, when it does not fit, it keeps
/// content ranked after it out of the datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SendRank {
    /// Its rank.
    pub priority: SendPriority,
    /// Whether it holds its place when it does not fit.
    pub holds_place: bool,
}

/// What [`RankedSendStrategy`] needs of an intent: its rank. The parts
/// implement it for their intents; a sum of intents ranks as the one it
/// holds.
pub trait RankedIntent {
    /// Where the intent ranks.
    fn rank(&self) -> SendRank;
}

impl RankedIntent for CNil {
    fn rank(&self) -> SendRank {
        match *self {}
    }
}

impl<H: RankedIntent, T: RankedIntent> RankedIntent for Coproduct<H, T> {
    fn rank(&self) -> SendRank {
        match self {
            Coproduct::Inl(intent) => intent.rank(),
            Coproduct::Inr(rest) => rest.rank(),
        }
    }
}

// ---- tickets ----

const WAITING: u8 = 0;
const CONSUMED: u8 = 1;
const WITHDRAWN: u8 = 2;
const ENDED: u8 = 3;

/// The state of one intent, shared by the strategy and the intent's
/// ticket: consuming and withdrawing are ordered by it, so only one of them
/// happens.
#[derive(Debug)]
struct IntentCell {
    state: AtomicU8,
}

impl IntentCell {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(WAITING),
        })
    }

    fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    fn is_waiting(&self) -> bool {
        self.state() == WAITING
    }

    fn leave_waiting(&self, to: u8) -> bool {
        self.state
            .compare_exchange(WAITING, to, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// The ticket of an intent published for any active link path: dropping
/// it withdraws the intent. `C` is what this endpoint's reason to close
/// holds.
pub struct IntentTicket<C> {
    cell: Arc<IntentCell>,
    closed: Arc<OnceLock<CloseReason<C>>>,
}

impl<C> fmt::Debug for IntentTicket<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntentTicket")
            .field("state", &self.cell.state())
            .finish_non_exhaustive()
    }
}

impl<C> IntentTicket<C> {
    /// Where the intent stands.
    pub fn state(&self) -> IntentState<ConnectionClosedError<C>> {
        match self.cell.state() {
            WAITING => IntentState::Waiting,
            CONSUMED => IntentState::Consumed,
            WITHDRAWN => IntentState::Withdrawn,
            // An intent of the core ends only once the close reason is set.
            _ => IntentState::Ended(ConnectionClosedError::new(
                self.closed
                    .get()
                    .cloned()
                    .expect("an ended intent has its close reason"),
            )),
        }
    }
}

impl<C> Drop for IntentTicket<C> {
    fn drop(&mut self) {
        self.cell.leave_waiting(WITHDRAWN);
    }
}

/// The ticket of an intent published on a link path's planner: dropping it
/// withdraws the intent.
#[derive(Debug)]
pub struct LinkPathIntentTicket {
    cell: Arc<IntentCell>,
}

impl LinkPathIntentTicket {
    /// Whether the intent is still waiting to be sent.
    pub fn is_waiting(&self) -> bool {
        self.cell.is_waiting()
    }
}

impl Drop for LinkPathIntentTicket {
    fn drop(&mut self) {
        self.cell.leave_waiting(WITHDRAWN);
    }
}

// ---- the core ----

#[derive(Debug)]
struct Entry<J> {
    intent: J,
    cell: Arc<IntentCell>,
}

#[derive(Debug)]
struct LinkPathEntry<Id> {
    id: Id,
    waker: Option<Waker>,
}

/// The core of the ranked strategy, for the composition's types `I`.
pub struct RankedSendStrategy<I: SendStrategyTypes> {
    intents: Vec<Entry<I::SendIntents>>,
    link_paths: Vec<LinkPathEntry<I::LinkPathIdentifier>>,
    keys: [bool; 4],
    handshake_confirmed: bool,
    closed: Arc<OnceLock<CloseReason<I::CloseCause>>>,
}

impl<I: SendStrategyTypes> fmt::Debug for RankedSendStrategy<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RankedSendStrategy")
            .field("intents", &self.intents.len())
            .field("link_paths", &self.link_paths.len())
            .field("keys", &self.keys)
            .field("handshake_confirmed", &self.handshake_confirmed)
            .finish_non_exhaustive()
    }
}

impl<I: SendStrategyTypes> Default for RankedSendStrategy<I> {
    fn default() -> Self {
        Self::new()
    }
}

fn level_index(level: EncryptionLevel) -> usize {
    match level {
        EncryptionLevel::Initial => 0,
        EncryptionLevel::ZeroRtt => 1,
        EncryptionLevel::Handshake => 2,
        EncryptionLevel::OneRtt => 3,
    }
}

fn level_of(kind: PlannedPacketKind) -> EncryptionLevel {
    match kind {
        PlannedPacketKind::Initial => EncryptionLevel::Initial,
        PlannedPacketKind::Handshake => EncryptionLevel::Handshake,
        PlannedPacketKind::ZeroRtt => EncryptionLevel::ZeroRtt,
        PlannedPacketKind::OneRtt
        | PlannedPacketKind::OneRttProbe
        | PlannedPacketKind::SettlingResponse => EncryptionLevel::OneRtt,
    }
}

impl<I: SendStrategyTypes> RankedSendStrategy<I> {
    /// A core with no intents, no link paths and no send keys yet.
    pub fn new() -> Self {
        Self {
            intents: Vec::new(),
            link_paths: Vec::new(),
            keys: [false; 4],
            handshake_confirmed: false,
            closed: Arc::new(OnceLock::new()),
        }
    }

    fn wake_all(&mut self) {
        for link_path in &mut self.link_paths {
            if let Some(waker) = link_path.waker.take() {
                waker.wake();
            }
        }
    }

    fn can_send(&self, kind: PlannedPacketKind) -> bool {
        let level = level_of(kind);
        if self.handshake_confirmed
            && matches!(level, EncryptionLevel::Initial | EncryptionLevel::Handshake)
        {
            return false;
        }
        self.keys[level_index(level)]
    }
}

impl<I: SendStrategyTypes, J: SendIntent> PublishOutcome<J, AnyActiveLinkPath>
    for RankedSendStrategy<I>
{
    type Outcome = IntentTicket<I::CloseCause>;
}

impl<I, J, Idx> PublishTo<J, AnyActiveLinkPath, Idx> for RankedSendStrategy<I>
where
    I: SendStrategyTypes,
    J: SendIntent,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish_to(&mut self, intent: J, _: AnyActiveLinkPath) -> IntentTicket<I::CloseCause> {
        let cell = IntentCell::new();
        if self.closed.get().is_some() {
            cell.leave_waiting(ENDED);
        } else {
            self.intents.push(Entry {
                intent: <I::SendIntents as InjectSendIntent<J, Idx>>::inject(intent),
                cell: Arc::clone(&cell),
            });
            self.wake_all();
        }
        IntentTicket {
            cell,
            closed: Arc::clone(&self.closed),
        }
    }
}

impl<I> SendStrategy<I> for RankedSendStrategy<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
    I::LinkPathIdentifier: Clone + PartialEq,
{
    type Destination = AnyActiveLinkPath;
    type LinkPathSendPlanner = RankedLinkPathSendPlanner<I>;

    fn add_link_path(
        &mut self,
        id: I::LinkPathIdentifier,
        role: LinkPathRoleKind,
    ) -> Self::LinkPathSendPlanner {
        self.link_paths.push(LinkPathEntry {
            id: id.clone(),
            waker: None,
        });
        RankedLinkPathSendPlanner {
            id,
            role,
            limits: None,
            overheads: PacketOverheads::default(),
            intents: Vec::new(),
            waker: None,
            thresholds: Thresholds::default(),
            close_resends: CloseResends::default(),
            types: PhantomData,
        }
    }

    fn send_keys_available(&mut self, level: EncryptionLevel) {
        self.keys[level_index(level)] = true;
        self.wake_all();
    }

    fn handshake_confirmed(&mut self) {
        self.handshake_confirmed = true;
        self.wake_all();
    }

    fn no_more_active_link_paths(&mut self, reason: CloseReason<I::CloseCause>) {
        let _ = self.closed.set(reason);
        for entry in self.intents.drain(..) {
            entry.cell.leave_waiting(ENDED);
        }
    }
}

// ---- the planner ----

/// The least room blocked content needs, for each flight class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Thresholds {
    ack_only: Option<usize>,
    in_flight: Option<usize>,
}

impl Thresholds {
    fn add(&mut self, class: FlightClass, need: usize) {
        let slot = match class {
            FlightClass::AckOnly => &mut self.ack_only,
            FlightClass::InFlight => &mut self.in_flight,
        };
        *slot = Some(slot.map_or(need, |least| least.min(need)));
    }

    fn reached_by(&self, limits: &DatagramLimits) -> bool {
        self.ack_only
            .is_some_and(|need| limits.capacity_for(FlightClass::AckOnly) >= need)
            || self
                .in_flight
                .is_some_and(|need| limits.capacity_for(FlightClass::InFlight) >= need)
    }
}

/// When a closing link path sends its close packet again: how many
/// datagrams it received while closing, and whether a resend is due.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CloseResends {
    received: u64,
    due: bool,
}

impl CloseResends {
    /// What happened, as `intent` tells: a sealed close packet goes out;
    /// of the datagrams received, those whose count is a power of two make
    /// it go again.
    fn note(&mut self, intent: ResendCloseIntent) {
        match intent {
            ResendCloseIntent::Sealed => self.due = true,
            ResendCloseIntent::DatagramReceived => {
                self.received = self.received.saturating_add(1);
                self.due |= self.received.is_power_of_two();
            }
        }
    }
}

/// The planner of one link path in the ranked strategy.
pub struct RankedLinkPathSendPlanner<I: SendStrategyTypes> {
    id: I::LinkPathIdentifier,
    role: LinkPathRoleKind,
    limits: Option<DatagramLimits>,
    overheads: PacketOverheads,
    intents: Vec<Entry<I::SendIntents>>,
    waker: Option<Waker>,
    thresholds: Thresholds,
    close_resends: CloseResends,
    types: PhantomData<fn() -> I>,
}

impl<I: SendStrategyTypes> fmt::Debug for RankedLinkPathSendPlanner<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RankedLinkPathSendPlanner")
            .field("role", &self.role)
            .field("limits", &self.limits)
            .field("overheads", &self.overheads)
            .field("intents", &self.intents.len())
            .field("close_resends", &self.close_resends)
            .finish_non_exhaustive()
    }
}

impl<I: SendStrategyTypes> RankedLinkPathSendPlanner<I> {
    fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

/// A part's intent, which ranks, gives back its ticket, or itself when the
/// role does not take it.
impl<I: SendStrategyTypes, J: SendIntent + RankedIntent> PublishOutcome<J, PlannerLinkPath>
    for RankedLinkPathSendPlanner<I>
{
    type Outcome = Result<LinkPathIntentTicket, IntentRejected<J>>;
}

/// A resend of the close packet gives back nothing.
impl<I: SendStrategyTypes> PublishOutcome<ResendCloseIntent, PlannerLinkPath>
    for RankedLinkPathSendPlanner<I>
{
    type Outcome = ();
}

/// Only an active link path takes a part's intents.
impl<I, J, Idx> Publish<J, Idx> for RankedLinkPathSendPlanner<I>
where
    I: SendStrategyTypes,
    J: SendIntent + RankedIntent,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish(&mut self, intent: J) -> Result<LinkPathIntentTicket, IntentRejected<J>> {
        if self.role != LinkPathRoleKind::Active {
            return Err(IntentRejected::new(
                intent,
                LinkPathPublishError::from(RoleNotAcceptingError::new(self.role)),
            ));
        }
        let cell = IntentCell::new();
        self.intents.push(Entry {
            intent: <I::SendIntents as InjectSendIntent<J, Idx>>::inject(intent),
            cell: Arc::clone(&cell),
        });
        self.wake();
        Ok(LinkPathIntentTicket { cell })
    }
}

/// The close packet of a link path that is not draining is sent again as
/// the module documentation says; one published before the planner was
/// told the link path closes waits until it is.
impl<I: SendStrategyTypes> Publish<ResendCloseIntent, ()> for RankedLinkPathSendPlanner<I> {
    fn publish(&mut self, intent: ResendCloseIntent) {
        if self.role == LinkPathRoleKind::Draining {
            return;
        }
        let due = self.close_resends.due;
        self.close_resends.note(intent);
        if self.close_resends.due && !due && self.role == LinkPathRoleKind::Closing {
            self.wake();
        }
    }
}

impl<I: SendStrategyTypes> Observe<DatagramLimits> for RankedLinkPathSendPlanner<I> {
    fn observe(&mut self, limits: DatagramLimits) {
        if self.limits == Some(limits) {
            return;
        }
        self.limits = Some(limits);
        if self.thresholds.reached_by(&limits) {
            self.wake();
        }
    }
}

impl<I: SendStrategyTypes> Observe<PacketOverheads> for RankedLinkPathSendPlanner<I> {
    fn observe(&mut self, overheads: PacketOverheads) {
        if self.overheads == overheads {
            return;
        }
        self.overheads = overheads;
        self.wake();
    }
}

/// Where a planned intent is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Core(usize),
    LinkPath(usize),
}

#[derive(Debug, Clone, Copy)]
struct PlannedEntry {
    held: Held,
    min: MinimumLengths,
    class: FlightClass,
}

#[derive(Debug)]
struct PacketPlan {
    kind: PlannedPacketKind,
    items: Vec<PlannedEntry>,
}

/// The kinds of packet a link path in `role` sends, in the order an
/// intent's packet is chosen: the first one with keys that can carry it.
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

impl<I> RankedLinkPathSendPlanner<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
{
    /// The packets of the next datagram, and the thresholds of what does
    /// not fit.
    fn plan_packets(&self, core: &RankedSendStrategy<I>) -> (Vec<PacketPlan>, Thresholds) {
        let mut thresholds = Thresholds::default();
        let Some(limits) = self.limits else {
            return (Vec::new(), thresholds);
        };
        let from_core = if self.role == LinkPathRoleKind::Active {
            core.intents.as_slice()
        } else {
            &[]
        };
        let mut candidates = Vec::new();
        let held = from_core
            .iter()
            .enumerate()
            .map(|(index, entry)| (Held::Core(index), entry))
            .chain(
                self.intents
                    .iter()
                    .enumerate()
                    .map(|(index, entry)| (Held::LinkPath(index), entry)),
            );
        for (held, entry) in held {
            if !entry.cell.is_waiting() {
                continue;
            }
            let Some(&kind) = kinds_of(self.role)
                .iter()
                .find(|&&kind| core.can_send(kind) && carries::<I>(kind, &entry.intent))
            else {
                continue;
            };
            candidates.push((
                entry.intent.rank(),
                level_of(kind),
                held,
                kind,
                &entry.intent,
            ));
        }
        candidates.sort_by_key(|&(rank, level, held, ..)| (rank.priority, level, held_order(held)));

        let mut packets: Vec<PacketPlan> = Vec::new();
        let mut highest: Option<EncryptionLevel> = None;
        for (rank, level, held, kind, intent) in candidates {
            if highest.is_some_and(|highest| level < highest) {
                break;
            }
            let min = I::min_lengths(intent);
            let class = I::flight_class(intent);
            // a kind of packet the link path cannot send now: no room
            // lets it go, so it holds no place and leaves no threshold
            let Some(overhead) = self.overheads.of(kind) else {
                continue;
            };
            let mut class_of_datagram = class;
            let mut need = overhead + min.as_last;
            if kind == PlannedPacketKind::Initial
                && (self.overheads.expands_every_initial || class == FlightClass::InFlight)
            {
                need = need.max(DatagramLimits::MINIMUM);
                class_of_datagram = FlightClass::InFlight;
            }
            if need > limits.capacity_for(class_of_datagram) {
                thresholds.add(class_of_datagram, need);
                if rank.holds_place {
                    break;
                }
                continue;
            }
            highest = Some(level);
            match packets.last_mut() {
                Some(packet) if packet.kind == kind => {
                    packet.items.push(PlannedEntry { held, min, class })
                }
                _ => packets.push(PacketPlan {
                    kind,
                    items: vec![PlannedEntry { held, min, class }],
                }),
            }
        }
        (packets, thresholds)
    }
}

fn held_order(held: Held) -> (u8, usize) {
    match held {
        Held::LinkPath(index) => (0, index),
        Held::Core(index) => (1, index),
    }
}

impl<I> LinkPathSendPlanner<I> for RankedLinkPathSendPlanner<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
    I::LinkPathIdentifier: Clone + PartialEq,
{
    type Core = RankedSendStrategy<I>;
    type Plan<'a>
        = RankedPlan<'a, I>
    where
        Self: 'a;

    fn poll_plan<'a>(
        &'a mut self,
        core: &'a mut Self::Core,
        cx: &mut Context<'_>,
    ) -> Poll<PlannedDatagram<Self::Plan<'a>>> {
        if self.role == LinkPathRoleKind::Closing {
            if core::mem::take(&mut self.close_resends.due) {
                return Poll::Ready(PlannedDatagram::ResendClose);
            }
            self.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        self.intents.retain(|entry| entry.cell.is_waiting());
        core.intents.retain(|entry| entry.cell.is_waiting());
        let (packets, thresholds) = self.plan_packets(core);
        if packets.is_empty() {
            self.thresholds = thresholds;
            self.waker = Some(cx.waker().clone());
            if let Some(entry) = core.link_paths.iter_mut().find(|entry| entry.id == self.id) {
                entry.waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        self.thresholds = Thresholds::default();
        Poll::Ready(PlannedDatagram::Fill(RankedPlan {
            core,
            planner: self,
            packets,
            next_packet: 0,
            feedback: RankedFeedback::default(),
        }))
    }

    fn role_changed(&mut self, _: &mut Self::Core, role: LinkPathRoleKind) {
        if self.role == role {
            return;
        }
        self.role = role;
        if role != LinkPathRoleKind::Active {
            for entry in self.intents.drain(..) {
                entry.cell.leave_waiting(ENDED);
            }
        }
        if role == LinkPathRoleKind::Draining {
            self.close_resends = CloseResends::default();
        }
        self.wake();
    }

    fn ended(self, core: &mut Self::Core) {
        core.link_paths.retain(|entry| entry.id != self.id);
        for entry in &self.intents {
            entry.cell.leave_waiting(ENDED);
        }
    }
}

// ---- the plan ----

/// What the ranked plan learns from each supply.
#[derive(Debug, Default)]
pub struct RankedFeedback {
    current: Option<Held>,
    consumed: Vec<Held>,
    stopped: bool,
}

impl SupplyFeedback for RankedFeedback {
    fn supplied(&mut self, written: usize) {
        if let Some(held) = self.current.take()
            && written > 0
        {
            self.consumed.push(held);
        }
    }
}

/// The plan of one datagram in the ranked strategy.
pub struct RankedPlan<'a, I: SendStrategyTypes> {
    core: &'a mut RankedSendStrategy<I>,
    planner: &'a mut RankedLinkPathSendPlanner<I>,
    packets: Vec<PacketPlan>,
    next_packet: usize,
    feedback: RankedFeedback,
}

impl<I: SendStrategyTypes> fmt::Debug for RankedPlan<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RankedPlan")
            .field("packets", &self.packets)
            .field("next_packet", &self.next_packet)
            .field("feedback", &self.feedback)
            .finish_non_exhaustive()
    }
}

impl<I: SendStrategyTypes> RankedPlan<'_, I> {
    fn intent(&self, held: Held) -> &I::SendIntents {
        match held {
            Held::Core(index) => &self.core.intents[index].intent,
            Held::LinkPath(index) => &self.planner.intents[index].intent,
        }
    }

    fn leading_of(&self, packet: usize) -> Option<LeadingContent<I::FrameSourceId>> {
        if self.feedback.stopped {
            return None;
        }
        let packet = self.packets.get(packet)?;
        let first = packet.items.first()?;
        Some(LeadingContent {
            packet: packet.kind,
            source: I::frame_source(self.intent(first.held)),
            min: first.min,
            class: first.class,
        })
    }
}

impl<I: SendStrategyTypes> Drop for RankedPlan<'_, I> {
    fn drop(&mut self) {
        for held in self.feedback.consumed.drain(..) {
            let cell = match held {
                Held::Core(index) => &self.core.intents[index].cell,
                Held::LinkPath(index) => &self.planner.intents[index].cell,
            };
            cell.leave_waiting(CONSUMED);
        }
    }
}

impl<'a, I: SendStrategyTypes> DatagramFillPlan<I> for RankedPlan<'a, I> {
    type Feedback = RankedFeedback;
    type Initial<'p>
        = RankedCursor<'p, 'a, I, I::InitialFrameSources>
    where
        Self: 'p;
    type Handshake<'p>
        = RankedCursor<'p, 'a, I, I::HandshakeFrameSources>
    where
        Self: 'p;
    type ZeroRtt<'p>
        = RankedCursor<'p, 'a, I, I::ZeroRttFrameSources>
    where
        Self: 'p;
    type OneRtt<'p>
        = RankedCursor<'p, 'a, I, I::OneRttFrameSources>
    where
        Self: 'p;
    type OneRttProbe<'p>
        = RankedCursor<'p, 'a, I, I::ProbeFrameSources>
    where
        Self: 'p;
    type SettlingResponse<'p>
        = RankedCursor<'p, 'a, I, I::SettlingFrameSources>
    where
        Self: 'p;

    fn leading_content(&self) -> Option<LeadingContent<I::FrameSourceId>> {
        self.leading_of(0)
    }

    fn peek_next_packet(&self) -> Option<LeadingContent<I::FrameSourceId>> {
        self.leading_of(self.next_packet)
    }

    fn next_packet(&mut self) -> Option<PlannedPacket<'_, I, Self>> {
        if self.feedback.stopped || self.next_packet >= self.packets.len() {
            return None;
        }
        let packet = self.next_packet;
        self.next_packet += 1;
        let kind = self.packets[packet].kind;
        Some(match kind {
            PlannedPacketKind::Initial => PlannedPacket::Initial(RankedCursor::new(self, packet)),
            PlannedPacketKind::Handshake => {
                PlannedPacket::Handshake(RankedCursor::new(self, packet))
            }
            PlannedPacketKind::ZeroRtt => PlannedPacket::ZeroRtt(RankedCursor::new(self, packet)),
            PlannedPacketKind::OneRtt => PlannedPacket::OneRtt(RankedCursor::new(self, packet)),
            PlannedPacketKind::OneRttProbe => {
                PlannedPacket::OneRttProbe(RankedCursor::new(self, packet))
            }
            PlannedPacketKind::SettlingResponse => {
                PlannedPacket::SettlingResponse(RankedCursor::new(self, packet))
            }
        })
    }
}

/// The cursor over one packet of a ranked plan, whose frame sources are
/// the set `S`.
pub struct RankedCursor<'p, 'a, I: SendStrategyTypes, S> {
    plan: &'p mut RankedPlan<'a, I>,
    packet: usize,
    next_item: usize,
    sources: PhantomData<fn() -> S>,
}

impl<I: SendStrategyTypes, S> fmt::Debug for RankedCursor<'_, '_, I, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RankedCursor")
            .field("packet", &self.packet)
            .field("next_item", &self.next_item)
            .finish_non_exhaustive()
    }
}

impl<'p, 'a, I: SendStrategyTypes, S> RankedCursor<'p, 'a, I, S> {
    fn new(plan: &'p mut RankedPlan<'a, I>, packet: usize) -> Self {
        Self {
            plan,
            packet,
            next_item: 0,
            sources: PhantomData,
        }
    }
}

impl<I, S> FrameSourceCursor<S> for RankedCursor<'_, '_, I, S>
where
    I: SendStrategyTypes,
    S: FrameSourceSet<Intents = I::SendIntents>,
{
    type Feedback = RankedFeedback;

    fn next(&mut self) -> Option<PlannedItem<'_, S::Item<'_>, RankedFeedback>> {
        let plan = &mut *self.plan;
        if plan.feedback.current.take().is_some() {
            // The last item was dropped without being supplied: it did not
            // fit, and nothing after it goes into this datagram.
            plan.feedback.stopped = true;
        }
        if plan.feedback.stopped {
            return None;
        }
        let items = &plan.packets[self.packet].items;
        let entry = *items.get(self.next_item)?;
        self.next_item += 1;
        let last_in_packet = self.next_item == items.len();
        let intent = match entry.held {
            Held::Core(index) => &plan.core.intents[index].intent,
            Held::LinkPath(index) => &plan.planner.intents[index].intent,
        };
        // The packet's kind was chosen because its set carries the intent.
        let item = S::item(intent)?;
        plan.feedback.current = Some(entry.held);
        Some(PlannedItem::new(
            item,
            entry.min,
            entry.class,
            last_in_packet,
            &mut plan.feedback,
        ))
    }
}

#[cfg(test)]
mod tests;
