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
//!
//! Application data goes by urgency ([`RankedIntent::urgency`]): a smaller
//! urgency always before a larger one, and within one urgency in turns,
//! each datagram starting after the intent that was given its turn last on
//! the link path. Application data that does not fit is passed over.
//!
//! A supply that writes something consumes its intent, except an intent
//! that stays after writing ([`RankedIntent::stays_after_writing`]), such as
//! a stream's data: its source wrote as much as it could and resized or
//! withdrew it, and the next plan takes it by the room it needs then. An
//! intent claimed before writing ([`RankedIntent::claimed_before_writing`]),
//! such as a DATAGRAM, is consumed before its source is given it, so that
//! withdrawing it on another thread either takes place first, and the
//! source is not given it, or reports it consumed.
//!
//! Intents published through the intake ([`RankedSendIntake`]), from the
//! application's threads or from the driver while it holds the core, wait
//! in a zone the core shares with the intake and the tickets, under a lock
//! nothing else is taken under: the core takes them in when a planner
//! plans. A planner that waits for content leaves there, for its link
//! path, the room its next datagram has and its waker; an intent published
//! or resized that fits that room wakes it, one that does not is kept as a
//! threshold the link path's conditions are compared with. A planner waits
//! only if nothing was published, resized or withdrawn there since it began
//! to plan; otherwise it plans again, so no wake-up is lost. Withdrawing a
//! waiting intent wakes the planners that something blocks, as the intent
//! may have been what blocked them.

use core::{
    fmt,
    marker::PhantomData,
    sync::atomic::{AtomicU8, Ordering},
    task::{Context, Poll, Waker},
};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use sakuya_stream::{
    connection::{CloseReason, ConnectionClosedError},
    send_options::urgency::Urgency,
};
use sakuya_wire::{
    parts::{CNil, Coproduct},
    v1::encryption_level::EncryptionLevel,
};

use super::{
    AnyActiveLinkPath, DatagramFillPlan, DatagramLimits, FrameSourceCursor, FrameSourceSet,
    InjectSendIntent, IntakeSendIntentHandle, IntentRejectedError, IntentState, IntentTicketResize,
    IntentTicketState, IntentTicketWithdraw, IntentWithdrawReport, LeadingContent,
    LinkPathPublishError, LinkPathRoleKind, LinkPathSendPlanner, MinimumLengths, Observe,
    PacketOverheads, PlannedDatagram, PlannedItem, PlannedPacket, PlannedPacketKind,
    PlannerLinkPath, Publish, PublishOutcome, PublishTo, ResendCloseIntent, RoleNotAcceptingError,
    SendIntent, SendIntentIntake, SendStrategy, SendStrategyTypes, SharedPublishTo, SupplyFeedback,
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

    /// How urgent the intent is among application data
    /// ([`SendPriority::ApplicationData`]): a smaller urgency goes first.
    /// Other ranks do not read it. The default urgency of RFC 9218 unless
    /// the intent gives its own.
    fn urgency(&self) -> Urgency {
        Urgency::default()
    }

    /// Whether the intent stays after a supply that wrote something: the
    /// strategy does not consume it, and its frame source, which may have
    /// written part of what it wants, resizes or withdraws it under its own
    /// lock before the supply returns. An intent that stays is planned again
    /// by the least room its ticket gives then. By default an intent is
    /// consumed by the first supply that writes anything.
    fn stays_after_writing(&self) -> bool {
        false
    }

    /// Whether the intent is consumed before its source is given it, rather
    /// than after its source wrote something: for an intent whose content
    /// is fixed in it and whose withdrawing no component's lock orders
    /// against its supply, such as a DATAGRAM. Withdrawing it on another
    /// thread then either takes place before the supply, and its source is
    /// not given it, or reports it consumed. Read only for an intent that
    /// does not stay after writing. By default an intent is not.
    fn claimed_before_writing(&self) -> bool {
        false
    }
}

impl RankedIntent for CNil {
    fn rank(&self) -> SendRank {
        match *self {}
    }

    fn urgency(&self) -> Urgency {
        match *self {}
    }

    fn stays_after_writing(&self) -> bool {
        match *self {}
    }

    fn claimed_before_writing(&self) -> bool {
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

    fn urgency(&self) -> Urgency {
        match self {
            Coproduct::Inl(intent) => intent.urgency(),
            Coproduct::Inr(rest) => rest.urgency(),
        }
    }

    fn stays_after_writing(&self) -> bool {
        match self {
            Coproduct::Inl(intent) => intent.stays_after_writing(),
            Coproduct::Inr(rest) => rest.stays_after_writing(),
        }
    }

    fn claimed_before_writing(&self) -> bool {
        match self {
            Coproduct::Inl(intent) => intent.claimed_before_writing(),
            Coproduct::Inr(rest) => rest.claimed_before_writing(),
        }
    }
}

// ---- tickets ----

const WAITING: u8 = 0;
const CONSUMED: u8 = 1;
const WITHDRAWN: u8 = 2;
const ENDED: u8 = 3;

/// What `mutex` holds, whether or not a holder panicked: every holder
/// writes whole values, so nothing is left half-written.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The state of one intent, shared by the strategy and the intent's
/// ticket: consuming and withdrawing are ordered by it, so only one of them
/// happens. It also holds the least room the intent needs now, which
/// resizing the ticket changes; its lock is taken under no other lock and
/// takes none.
#[derive(Debug)]
struct IntentCell {
    state: AtomicU8,
    min: Mutex<MinimumLengths>,
    class: FlightClass,
}

impl IntentCell {
    fn new(min: MinimumLengths, class: FlightClass) -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(WAITING),
            min: Mutex::new(min),
            class,
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

    fn min(&self) -> MinimumLengths {
        *lock(&self.min)
    }

    fn resize(&self, min: MinimumLengths) {
        *lock(&self.min) = min;
    }
}

/// The ticket of an intent published for any active link path: dropping
/// it withdraws the intent. `C` is what this endpoint's reason to close
/// holds.
pub struct IntentTicket<C> {
    cell: Arc<IntentCell>,
    zone: Arc<SyncZone<C>>,
}

impl<C> fmt::Debug for IntentTicket<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntentTicket")
            .field("state", &self.cell.state())
            .finish_non_exhaustive()
    }
}

impl<C> IntentTicket<C> {
    /// Why an ended intent ended.
    fn ended(&self) -> ConnectionClosedError<C> {
        // An intent of the core ends only once the close reason is set.
        ConnectionClosedError::new(
            self.zone
                .closed
                .get()
                .cloned()
                .expect("an ended intent has its close reason"),
        )
    }
}

impl<C> IntentTicketState for IntentTicket<C> {
    type End = ConnectionClosedError<C>;

    fn state(&self) -> IntentState<ConnectionClosedError<C>> {
        match self.cell.state() {
            WAITING => IntentState::Waiting,
            CONSUMED => IntentState::Consumed,
            WITHDRAWN => IntentState::Withdrawn,
            _ => IntentState::Ended(self.ended()),
        }
    }
}

/// Resizing a waiting intent tells the planners waiting for content: one
/// whose room it now fits is woken.
impl<C> IntentTicketResize for IntentTicket<C> {
    fn resize(&mut self, min: MinimumLengths) {
        self.cell.resize(min);
        if self.cell.is_waiting() {
            self.zone.content_changed(ContentChange::Needs {
                class: self.cell.class,
                need: min.as_last,
            });
        }
    }
}

/// Withdrawing and the supply's claim are ordered by the intent's state:
/// only one of them takes place, so a withdrawal reported as having taken
/// place leaves the intent out of every packet, and one that comes after
/// the claim reports it consumed.
impl<C> IntentTicketWithdraw for IntentTicket<C> {
    type Report = IntentWithdrawReport<ConnectionClosedError<C>>;

    fn withdraw(self) -> Self::Report {
        if self.cell.leave_waiting(WITHDRAWN) {
            self.zone.content_changed(ContentChange::Withdrawn);
            return IntentWithdrawReport::Withdrawn;
        }
        // The intent left waiting, and only this ticket withdraws it: it
        // was consumed or it ended.
        match self.cell.state() {
            CONSUMED => IntentWithdrawReport::Consumed,
            _ => IntentWithdrawReport::Ended(self.ended()),
        }
    }
}

impl<C> Drop for IntentTicket<C> {
    fn drop(&mut self) {
        if self.cell.leave_waiting(WITHDRAWN) {
            self.zone.content_changed(ContentChange::Withdrawn);
        }
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

// ---- the zone shared with the intake and the tickets ----

/// The room a link path's next datagram has, for each flight class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Room {
    ack_only: usize,
    in_flight: usize,
}

impl Room {
    fn of(limits: &DatagramLimits) -> Self {
        Self {
            ack_only: limits.capacity_for(FlightClass::AckOnly),
            in_flight: limits.capacity_for(FlightClass::InFlight),
        }
    }

    fn fits(&self, class: FlightClass, need: usize) -> bool {
        match class {
            FlightClass::AckOnly => need <= self.ack_only,
            FlightClass::InFlight => need <= self.in_flight,
        }
    }
}

/// What a link path's planner left in the zone when it last began to wait.
#[derive(Debug)]
struct LinkPathWait {
    serial: u64,
    /// Taken when it is woken, and when the planner plans again.
    waker: Option<Waker>,
    /// Whether the link path takes intents for any active link path.
    accepts: bool,
    /// The room of its next datagram; `None` while it was told none.
    room: Option<Room>,
    /// The least room needed by content published or resized while it
    /// waits that did not fit its room.
    unplanned: Thresholds,
    /// Whether it left content that did not fit.
    blocked: bool,
}

impl LinkPathWait {
    fn new(serial: u64) -> Self {
        Self {
            serial,
            waker: None,
            accepts: false,
            room: None,
            unplanned: Thresholds::default(),
            blocked: false,
        }
    }
}

#[derive(Debug, Default)]
struct Waits {
    /// Counts the changes of content made in the zone; a planner that
    /// began to plan at another count plans again instead of waiting.
    changes: u64,
    link_paths: Vec<LinkPathWait>,
}

/// How content changed outside the driver's borrows.
#[derive(Debug, Clone, Copy)]
enum ContentChange {
    /// Content of `class` needing at least `need` bytes was published or
    /// resized.
    Needs { class: FlightClass, need: usize },
    /// A waiting intent was withdrawn.
    Withdrawn,
}

/// What the core shares with its intake and its tickets: the reason the
/// connection closed, and what each link path's planner needs to be woken.
#[derive(Debug)]
struct SyncZone<C> {
    closed: OnceLock<CloseReason<C>>,
    waits: Mutex<Waits>,
}

impl<C> SyncZone<C> {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            closed: OnceLock::new(),
            waits: Mutex::new(Waits::default()),
        })
    }

    /// Count `change`, and wake the waiting planners it may let send: the
    /// zone is let go before they are woken.
    fn content_changed(&self, change: ContentChange) {
        let mut woken = Vec::new();
        {
            let mut waits = lock(&self.waits);
            waits.changes = waits.changes.wrapping_add(1);
            for wait in &mut waits.link_paths {
                if !wait.accepts || wait.waker.is_none() {
                    continue;
                }
                let wake = match change {
                    ContentChange::Needs { class, need } => {
                        let fits = wait.room.is_some_and(|room| room.fits(class, need));
                        if !fits {
                            wait.unplanned.add(class, need);
                        }
                        fits
                    }
                    ContentChange::Withdrawn => wait.blocked,
                };
                if wake {
                    woken.extend(wait.waker.take());
                }
            }
        }
        for waker in woken {
            waker.wake();
        }
    }
}

// ---- the core ----

#[derive(Debug)]
struct Entry<J> {
    intent: J,
    cell: Arc<IntentCell>,
    /// When it was taken in, among the intents of its holder.
    order: u64,
}

/// An intent published through the intake, not yet taken in by the core.
#[derive(Debug)]
struct Published<J> {
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
    next_order: u64,
    next_serial: u64,
    published: Arc<Mutex<Vec<Published<I::SendIntents>>>>,
    zone: Arc<SyncZone<I::CloseCause>>,
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
            next_order: 0,
            next_serial: 0,
            published: Arc::new(Mutex::new(Vec::new())),
            zone: SyncZone::new(),
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

    /// Take in what was published through the intake.
    fn take_in_published(&mut self) {
        let next_order = &mut self.next_order;
        self.intents
            .extend(lock(&self.published).drain(..).map(|published| {
                let order = *next_order;
                *next_order += 1;
                Entry {
                    intent: published.intent,
                    cell: published.cell,
                    order,
                }
            }));
    }

    fn ticket(&self, cell: Arc<IntentCell>) -> IntentTicket<I::CloseCause> {
        IntentTicket {
            cell,
            zone: Arc::clone(&self.zone),
        }
    }
}

/// What [`RankedSendStrategy`] gives back for an intent published to its
/// core or its intake, by the type of the intent. The parts implement it
/// for the intents their components publish there.
pub trait RankedCoreIntent: SendIntent {
    /// [`IntentTicket`] for an intent someone reads or withdraws; `()` for
    /// one sent and forgotten, which only being supplied or the end of the
    /// connection takes away. `C` is what this endpoint's reason to close
    /// holds.
    type Outcome<C>: RankedCoreOutcome<C>;
}

/// What the core of [`RankedSendStrategy`] can give back for an intent:
/// [`IntentTicket`] or `()`.
pub trait RankedCoreOutcome<C>: sealed::CoreOutcome<C> {}

mod sealed {
    use super::IntentTicket;

    /// How the core gives back what it gives back for an intent, given how
    /// to make the intent's ticket.
    pub trait CoreOutcome<C> {
        fn new(ticket: impl FnOnce() -> IntentTicket<C>) -> Self;
    }

    impl<C> CoreOutcome<C> for IntentTicket<C> {
        fn new(ticket: impl FnOnce() -> IntentTicket<C>) -> Self {
            ticket()
        }
    }

    /// No ticket is made, so nothing withdraws the intent: its state stays
    /// with the core only.
    impl<C> CoreOutcome<C> for () {
        fn new(_: impl FnOnce() -> IntentTicket<C>) -> Self {}
    }
}

impl<C> RankedCoreOutcome<C> for IntentTicket<C> {}
impl<C> RankedCoreOutcome<C> for () {}

impl<I: SendStrategyTypes, J: RankedCoreIntent> PublishOutcome<J, AnyActiveLinkPath>
    for RankedSendStrategy<I>
{
    type Outcome = J::Outcome<I::CloseCause>;
}

impl<I, J, Idx> PublishTo<J, AnyActiveLinkPath, Idx> for RankedSendStrategy<I>
where
    I: SendStrategyTypes,
    J: RankedCoreIntent,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish_to(&mut self, intent: J, _: AnyActiveLinkPath) -> J::Outcome<I::CloseCause> {
        let intent = <I::SendIntents as InjectSendIntent<J, Idx>>::inject(intent);
        let cell = IntentCell::new(I::min_lengths(&intent), I::flight_class(&intent));
        if self.zone.closed.get().is_some() {
            cell.leave_waiting(ENDED);
        } else {
            let order = self.next_order;
            self.next_order += 1;
            self.intents.push(Entry {
                intent,
                cell: Arc::clone(&cell),
                order,
            });
            self.wake_all();
        }
        sealed::CoreOutcome::new(|| self.ticket(cell))
    }
}

/// The intake of the ranked strategy: intents published through it wait in
/// the zone it shares with the core until a planner of the core plans, and
/// end with the connection's close reason once the connection closed.
pub struct RankedSendIntake<I: SendStrategyTypes> {
    published: Arc<Mutex<Vec<Published<I::SendIntents>>>>,
    zone: Arc<SyncZone<I::CloseCause>>,
}

impl<I: SendStrategyTypes> Clone for RankedSendIntake<I> {
    fn clone(&self) -> Self {
        Self {
            published: Arc::clone(&self.published),
            zone: Arc::clone(&self.zone),
        }
    }
}

impl<I: SendStrategyTypes> fmt::Debug for RankedSendIntake<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RankedSendIntake").finish_non_exhaustive()
    }
}

impl<I: SendStrategyTypes, J: RankedCoreIntent> PublishOutcome<J, AnyActiveLinkPath>
    for RankedSendIntake<I>
{
    type Outcome = J::Outcome<I::CloseCause>;
}

impl<I, J, Idx> SharedPublishTo<J, AnyActiveLinkPath, Idx> for RankedSendIntake<I>
where
    I: SendStrategyTypes,
    J: RankedCoreIntent,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish_to(&self, intent: J, _: AnyActiveLinkPath) -> J::Outcome<I::CloseCause> {
        let intent = <I::SendIntents as InjectSendIntent<J, Idx>>::inject(intent);
        let min = I::min_lengths(&intent);
        let class = I::flight_class(&intent);
        let cell = IntentCell::new(min, class);
        // Whether the connection closed is read under the lock the close
        // takes the published intents under: none is left waiting.
        let taken = {
            let mut published = lock(&self.published);
            if self.zone.closed.get().is_some() {
                cell.leave_waiting(ENDED);
                false
            } else {
                published.push(Published {
                    intent,
                    cell: Arc::clone(&cell),
                });
                true
            }
        };
        if taken {
            self.zone.content_changed(ContentChange::Needs {
                class,
                need: min.as_last,
            });
        }
        sealed::CoreOutcome::new(|| IntentTicket {
            cell,
            zone: Arc::clone(&self.zone),
        })
    }
}

impl<I: SendStrategyTypes> SendIntentIntake<AnyActiveLinkPath> for RankedSendIntake<I> {
    type Handle<J: SendIntent, Idx>
        = IntakeSendIntentHandle<Self, J, Idx>
    where
        Self: SharedPublishTo<J, AnyActiveLinkPath, Idx>;

    fn handle<J: SendIntent, Idx>(&self) -> Self::Handle<J, Idx>
    where
        Self: SharedPublishTo<J, AnyActiveLinkPath, Idx>,
    {
        IntakeSendIntentHandle::new(self.clone())
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
    type Intake = RankedSendIntake<I>;

    fn intake(&self) -> RankedSendIntake<I> {
        RankedSendIntake {
            published: Arc::clone(&self.published),
            zone: Arc::clone(&self.zone),
        }
    }

    fn add_link_path(
        &mut self,
        id: I::LinkPathIdentifier,
        role: LinkPathRoleKind,
    ) -> Self::LinkPathSendPlanner {
        self.link_paths.push(LinkPathEntry {
            id: id.clone(),
            waker: None,
        });
        let serial = self.next_serial;
        self.next_serial += 1;
        lock(&self.zone.waits)
            .link_paths
            .push(LinkPathWait::new(serial));
        RankedLinkPathSendPlanner {
            id,
            serial,
            zone: Arc::clone(&self.zone),
            role,
            limits: None,
            overheads: PacketOverheads::default(),
            intents: Vec::new(),
            next_order: 0,
            waker: None,
            thresholds: Thresholds::default(),
            turns: [None; URGENCIES],
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
        let _ = self.zone.closed.set(reason);
        for entry in self.intents.drain(..) {
            entry.cell.leave_waiting(ENDED);
        }
        for published in lock(&self.published).drain(..) {
            published.cell.leave_waiting(ENDED);
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

    fn is_empty(&self) -> bool {
        self.ack_only.is_none() && self.in_flight.is_none()
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

/// How many urgencies there are: `0` to `7`.
const URGENCIES: usize = 8;

/// Where an intent stands among the intents of one rank, level and urgency
/// when turns do not change it: the planner's own first, each holder's in
/// the order they were taken in.
type IntentOrder = (u8, u64);

fn intent_order(held: Held, order: u64) -> IntentOrder {
    match held {
        Held::LinkPath(_) => (0, order),
        Held::Core(_) => (1, order),
    }
}

/// The planner of one link path in the ranked strategy.
pub struct RankedLinkPathSendPlanner<I: SendStrategyTypes> {
    id: I::LinkPathIdentifier,
    serial: u64,
    zone: Arc<SyncZone<I::CloseCause>>,
    role: LinkPathRoleKind,
    limits: Option<DatagramLimits>,
    overheads: PacketOverheads,
    intents: Vec<Entry<I::SendIntents>>,
    next_order: u64,
    waker: Option<Waker>,
    thresholds: Thresholds,
    /// For each urgency of application data, the intent given its turn
    /// last: the next datagram starts after it.
    turns: [Option<IntentOrder>; URGENCIES],
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

    /// Begin to plan: what was published through the intake is taken in;
    /// the count of changes in the zone before it was taken in.
    fn begin(&self, core: &mut RankedSendStrategy<I>) -> u64 {
        let changes = {
            let mut waits = lock(&self.zone.waits);
            if let Some(wait) = waits
                .link_paths
                .iter_mut()
                .find(|wait| wait.serial == self.serial)
            {
                wait.waker = None;
            }
            waits.changes
        };
        core.take_in_published();
        changes
    }

    /// Wait with `waker`, leaving in the zone what wakes this link path,
    /// unless the zone changed since the count `seen`: then plan again.
    fn wait(&self, seen: u64, waker: &Waker) -> bool {
        let waker = waker.clone();
        let mut waits = lock(&self.zone.waits);
        if waits.changes != seen {
            return false;
        }
        if let Some(wait) = waits
            .link_paths
            .iter_mut()
            .find(|wait| wait.serial == self.serial)
        {
            wait.waker = Some(waker);
            wait.accepts = self.role == LinkPathRoleKind::Active;
            wait.room = self.limits.as_ref().map(Room::of);
            wait.unplanned = Thresholds::default();
            wait.blocked = !self.thresholds.is_empty();
        }
        true
    }

    /// The link path is told `limits` while it may wait: its room in the
    /// zone follows, and whether content published meanwhile now fits.
    fn waiting_content_fits(&self, limits: &DatagramLimits) -> bool {
        let mut waits = lock(&self.zone.waits);
        let Some(wait) = waits
            .link_paths
            .iter_mut()
            .find(|wait| wait.serial == self.serial)
        else {
            return false;
        };
        if wait.waker.is_none() {
            return false;
        }
        wait.room = Some(Room::of(limits));
        wait.unplanned.reached_by(limits)
    }
}

/// A part's intent, which ranks, gives back its ticket, or itself when the
/// role does not take it.
impl<I: SendStrategyTypes, J: SendIntent + RankedIntent> PublishOutcome<J, PlannerLinkPath>
    for RankedLinkPathSendPlanner<I>
{
    type Outcome = Result<LinkPathIntentTicket, IntentRejectedError<J>>;
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
    fn publish(&mut self, intent: J) -> Result<LinkPathIntentTicket, IntentRejectedError<J>> {
        if self.role != LinkPathRoleKind::Active {
            return Err(IntentRejectedError::new(
                intent,
                LinkPathPublishError::from(RoleNotAcceptingError::new(self.role)),
            ));
        }
        let intent = <I::SendIntents as InjectSendIntent<J, Idx>>::inject(intent);
        let cell = IntentCell::new(I::min_lengths(&intent), I::flight_class(&intent));
        let order = self.next_order;
        self.next_order += 1;
        self.intents.push(Entry {
            intent,
            cell: Arc::clone(&cell),
            order,
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
        // Both are asked: the room in the zone follows the limits.
        let waiting_fits = self.waiting_content_fits(&limits);
        if self.thresholds.reached_by(&limits) || waiting_fits {
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
    /// For application data: its urgency and where it stands, to give the
    /// next turn after it once it is supplied.
    turn: Option<(usize, IntentOrder)>,
    /// Whether the intent stays after a supply that wrote something
    /// ([`RankedIntent::stays_after_writing`]).
    stays: bool,
    /// Whether the supply claims the intent before its source is given it
    /// ([`RankedIntent::claimed_before_writing`]); never for one that
    /// stays.
    claimed: bool,
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

/// An intent that may go into the next datagram, with what orders it.
struct Candidate<'e, J> {
    rank: SendRank,
    level: EncryptionLevel,
    /// The urgency of application data; `0` for other ranks.
    urgency: usize,
    /// Whether it had its turn in this urgency: those that had theirs go
    /// after those that did not.
    had_turn: bool,
    order: IntentOrder,
    held: Held,
    kind: PlannedPacketKind,
    entry: &'e Entry<J>,
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
            let rank = entry.intent.rank();
            let order = intent_order(held, entry.order);
            let (urgency, had_turn) = if rank.priority == SendPriority::ApplicationData {
                let urgency = usize::from(entry.intent.urgency().get());
                let had_turn = self.turns[urgency].is_some_and(|last| order <= last);
                (urgency, had_turn)
            } else {
                (0, false)
            };
            candidates.push(Candidate {
                rank,
                level: level_of(kind),
                urgency,
                had_turn,
                order,
                held,
                kind,
                entry,
            });
        }
        candidates.sort_by_key(|candidate| {
            (
                candidate.rank.priority,
                candidate.level,
                candidate.urgency,
                candidate.had_turn,
                candidate.order,
            )
        });

        let mut packets: Vec<PacketPlan> = Vec::new();
        let mut highest: Option<EncryptionLevel> = None;
        for candidate in candidates {
            let Candidate {
                rank,
                level,
                urgency,
                order,
                held,
                kind,
                entry,
                ..
            } = candidate;
            if highest.is_some_and(|highest| level < highest) {
                break;
            }
            let min = entry.cell.min();
            let class = entry.cell.class;
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
            let application_data = rank.priority == SendPriority::ApplicationData;
            if need > limits.capacity_for(class_of_datagram) {
                thresholds.add(class_of_datagram, need);
                // application data that does not fit is passed over
                if rank.holds_place && !application_data {
                    break;
                }
                continue;
            }
            highest = Some(level);
            let planned = PlannedEntry {
                held,
                min,
                class,
                turn: application_data.then_some((urgency, order)),
                stays: entry.intent.stays_after_writing(),
                claimed: !entry.intent.stays_after_writing()
                    && entry.intent.claimed_before_writing(),
            };
            match packets.last_mut() {
                Some(packet) if packet.kind == kind => packet.items.push(planned),
                _ => packets.push(PacketPlan {
                    kind,
                    items: vec![planned],
                }),
            }
        }
        (packets, thresholds)
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
        loop {
            let seen = self.begin(core);
            self.intents.retain(|entry| entry.cell.is_waiting());
            core.intents.retain(|entry| entry.cell.is_waiting());
            let (packets, thresholds) = self.plan_packets(core);
            if !packets.is_empty() {
                self.thresholds = Thresholds::default();
                return Poll::Ready(PlannedDatagram::Fill(RankedPlan {
                    core,
                    planner: self,
                    packets,
                    next_packet: 0,
                    feedback: RankedFeedback::default(),
                }));
            }
            self.thresholds = thresholds;
            self.waker = Some(cx.waker().clone());
            if let Some(entry) = core.link_paths.iter_mut().find(|entry| entry.id == self.id) {
                entry.waker = Some(cx.waker().clone());
            }
            if self.wait(seen, cx.waker()) {
                return Poll::Pending;
            }
        }
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
        lock(&self.zone.waits)
            .link_paths
            .retain(|wait| wait.serial != self.serial);
        for entry in &self.intents {
            entry.cell.leave_waiting(ENDED);
        }
    }
}

// ---- the plan ----

/// The item a cursor gave out and that is not yet supplied.
#[derive(Debug)]
struct CurrentItem {
    entry: PlannedEntry,
    /// Its intent's state, which claiming it changes.
    cell: Arc<IntentCell>,
}

/// What the ranked plan learns from each supply.
#[derive(Debug, Default)]
pub struct RankedFeedback {
    current: Option<CurrentItem>,
    /// The items supplied, in order, and whether each wrote anything.
    supplied: Vec<(PlannedEntry, bool)>,
    stopped: bool,
}

/// An item claimed before writing is consumed when it is claimed, before
/// its source is given it: the plan found that it fits (its least room as
/// the last frame), and what it is to write is fixed in the intent, so its
/// source writes it; should the source write nothing, the intent is
/// consumed all the same. Other items are not claimed: they are consumed
/// once the plan ends, if they wrote anything and do not stay.
impl SupplyFeedback for RankedFeedback {
    fn claim(&mut self) -> bool {
        match &self.current {
            Some(current) if current.entry.claimed => current.cell.leave_waiting(CONSUMED),
            _ => true,
        }
    }

    fn supplied(&mut self, written: usize) {
        if let Some(current) = self.current.take() {
            self.supplied.push((current.entry, written > 0));
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

/// The items supplied had their turn; those that wrote anything are
/// consumed, unless they stay after writing, as their sources already
/// resized or withdrew them, or they were consumed when they were claimed.
impl<I: SendStrategyTypes> Drop for RankedPlan<'_, I> {
    fn drop(&mut self) {
        for (entry, wrote) in self.feedback.supplied.drain(..) {
            if let Some((urgency, order)) = entry.turn {
                self.planner.turns[urgency] = Some(order);
            }
            if wrote && !entry.stays && !entry.claimed {
                let cell = match entry.held {
                    Held::Core(index) => &self.core.intents[index].cell,
                    Held::LinkPath(index) => &self.planner.intents[index].cell,
                };
                cell.leave_waiting(CONSUMED);
            }
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
        let held = match entry.held {
            Held::Core(index) => &plan.core.intents[index],
            Held::LinkPath(index) => &plan.planner.intents[index],
        };
        // The packet's kind was chosen because its set carries the intent.
        let item = S::item(&held.intent)?;
        plan.feedback.current = Some(CurrentItem {
            entry,
            cell: Arc::clone(&held.cell),
        });
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
