//! A send strategy that ranks content: acknowledgments first, then path
//! validation, the handshake, control frames, path MTU probes and
//! application data, and within a rank by encryption level.
//!
//! A plan orders content; whether an item fits is found when it is
//! written. Content that does not fit an empty datagram is not planned,
//! and leaves the least room it needs as a threshold: when it holds its
//! place, nothing ranked after it goes into the datagram, so it is not
//! starved by what comes later, unless it does not hold its place (a path
//! MTU probe, or content waiting for a larger datagram size). Each item
//! says whether it holds its place ([`PlannedItem::holds_place`]): one that
//! writes nothing ends the datagram when it does, and is passed over when it
//! does not. Content whose kind of packet the link path cannot send at all
//! now, as its keys are gone or no connection ID is offered, is passed over:
//! it holds no place and leaves no threshold, as no room would let it go. A
//! datagram's packets go in increasing encryption level: content of a lower
//! level than what is already planned yields, and with it everything after
//! it, to the next datagram.
//!
//! The core holds the intents published through the intake for any active
//! link path; what the driver's own components have to send comes with each
//! request for a plan ([`DriverContent`]), and the planner keeps none of
//! it. A planner with nothing to plan keeps, for each flight class, the
//! least room blocked content needs, and is woken when its observed
//! conditions reach it, when content is published, or when the keys or its
//! role change; the driver wakes the sending call when its own content
//! changes.
//!
//! A closing link path sends its close packet again
//! ([`PlannedDatagram::ResendClose`]) once it is sealed, and then for the
//! first, second, fourth, eighth and every further power of two among the
//! datagrams it received since ([`CloseResendFacts`]): the rate falls as the
//! peer keeps sending (RFC 9000 §10.2.1). The planner keeps how many had
//! arrived when it last sent the close packet again; a draining link path
//! sends nothing.
//!
//! Application data goes by urgency ([`RankedIntent::urgency`]): a smaller
//! urgency always before a larger one, and within one urgency in turns,
//! each datagram starting after the intent that was given its turn last on
//! the link path. Application data that does not fit is passed over.
//!
//! An ordinary 1-RTT STREAM waits to open a datagram while pacing alone
//! limits its size and the pacer has a release scheduled. The target is
//! the smaller of the path capacity and the available congestion window.
//! A probe permit lifts the wait. Another eligible source may open the
//! datagram first, after which the STREAM can use the remaining room.
//!
//! A path MTU probe ([`RankedIntent::exact_datagram_size`]) leads a
//! datagram of exactly its size, and nothing is planned after it: the
//! datagram carries its PING and the PADDING that brings it to the size.
//! Ranked after other content, it waits for a datagram that starts with
//! it; it goes when the whole size can go now
//! ([`DatagramLimits::pmtu_probe_capacity`]), past no permit, also while
//! the link path does not carry 1200 bytes and nothing else goes, and
//! leaves its size as a threshold when it cannot. While nothing else goes,
//! content that holds its place does not hold it against a probe.
//!
//! Content that only rides along ([`SendIntent::only_piggybacks`]), such as
//! an ACK frame the obligation wants in a packet sent anyway, opens no
//! packet and no datagram and leaves no threshold: once the rest of the
//! datagram is planned, it goes first into the packet of its kind, if the
//! plan has one, and after content that opens the datagram.
//!
//! A supply that writes something consumes its intent, except an intent
//! that stays after writing ([`RankedIntent::stays_after_writing`]), such as
//! a stream's data: its source wrote as much as it could and resized or
//! withdrew it, and the next plan takes it by the room it needs then. The
//! strategy does not order writing an intent against withdrawing it on
//! another thread: a frame source whose intents can be withdrawn so, such
//! as the DATAGRAM frames, orders the two by its own state.
//!
//! Intents published through the intake ([`RankedSendIntake`]), from the
//! application's threads, wait
//! in a zone the core shares with the intake and the tickets, under a lock
//! nothing else is taken under: the core takes them in when a planner
//! plans. A planner that waits for content leaves there, for its link
//! path, the room its next datagram has and its waker; an intent published
//! or resized that fits that room wakes it, one that does not is kept as a
//! threshold the link path's conditions are compared with. A planner waits
//! only if nothing was published, resized or withdrawn there since it began
//! to plan; otherwise it plans again, so no wake-up is lost. Withdrawing a
//! waiting intent wakes the planners that something blocks, as the intent
//! may have been what blocked them. A planner that gives out a plan leaves
//! its waker there as well, as one that something blocks: a sending call
//! that could not fill the plan waits without asking again, and what is
//! published after the plan wakes it.

use core::{
    fmt,
    marker::PhantomData,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    task::{Context, Poll, Waker},
};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use smallvec::SmallVec;

use sakuya_stream::{
    connection::{CloseReason, ConnectionClosedError},
    send_options::urgency::Urgency,
};
use sakuya_wire::parts::{CNil, Coproduct};
use sakuya_wire_v1::encryption_level::EncryptionLevel;

use super::{
    AnyActiveLinkPath, CloseResendFacts, DatagramFillPlan, DatagramLimits, DriverContent,
    FrameSourceCursor, FrameSourceSet, InjectSendIntent, IntakeSendIntentHandle, IntentState,
    IntentTicketChanges, IntentTicketRelease, IntentTicketResize, IntentTicketState,
    IntentTicketWithdraw, IntentWithdrawReport, LeadingContent, LinkPathRoleKind,
    LinkPathSendPlanner, MinimumLengths, Observe, PacketOverheads, PlanChange, PlannedDatagram,
    PlannedItem, PlannedPacket, PlannedPacketKind, PublishOutcome, PublishTo, SendIntent,
    SendIntentIntake, SendIntentPublisher, SendStrategy, SendStrategyTypes, SharedPublishTo,
    SharedSendStrategy, SupplyFeedback,
};
use sakuya_wire_v1::frame::write::FlightClass;

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

    /// Whether this intent supplies STREAM frames. An ordinary 1-RTT
    /// STREAM may ride with other content while pacing holds back the
    /// rest of the datagram it could otherwise open.
    fn is_stream(&self) -> bool {
        false
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

    /// The size of the whole datagram the intent goes in, if it is one of
    /// exactly that size, as a path MTU probe's
    /// ([`SendPriority::PathMtuProbe`]): it then leads its datagram, goes
    /// only when the link path can send a datagram of that size now
    /// ([`DatagramLimits::pmtu_probe_capacity`]), and nothing is planned
    /// after it. Other ranks do not read it. By default an intent takes
    /// what room the datagram has.
    fn exact_datagram_size(&self) -> Option<usize> {
        None
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

    fn exact_datagram_size(&self) -> Option<usize> {
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

    fn is_stream(&self) -> bool {
        match self {
            Coproduct::Inl(intent) => intent.is_stream(),
            Coproduct::Inr(rest) => rest.is_stream(),
        }
    }

    fn stays_after_writing(&self) -> bool {
        match self {
            Coproduct::Inl(intent) => intent.stays_after_writing(),
            Coproduct::Inr(rest) => rest.stays_after_writing(),
        }
    }

    fn exact_datagram_size(&self) -> Option<usize> {
        match self {
            Coproduct::Inl(intent) => intent.exact_datagram_size(),
            Coproduct::Inr(rest) => rest.exact_datagram_size(),
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

/// The ticket of an intent published through `&mut` to the publisher
/// (`KeyIntentTicket`): a key of the strategy's, with the intent's flight
/// class, and no state of its own. Its
/// intent is resized, withdrawn and let go through the publisher
/// ([`IntentTicketChanges`]); dropping it does nothing, and the intent
/// stays until it is consumed, withdrawn or ended.
#[must_use]
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct KeyIntentTicket {
    key: u64,
    class: FlightClass,
}

/// The state of one intent published through the intake, shared by the
/// strategy and the intent's ticket: consuming and withdrawing are ordered
/// by it, so only one of them happens. It also holds the least room the
/// intent needs now, which resizing the ticket changes, and whether the
/// intent waits as too large; its lock is taken under no other lock and
/// takes none.
#[derive(Debug)]
struct IntentCell {
    state: AtomicU8,
    too_large: AtomicBool,
    min: Mutex<MinimumLengths>,
    class: FlightClass,
}

impl IntentCell {
    fn new(min: MinimumLengths, class: FlightClass) -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(WAITING),
            too_large: AtomicBool::new(false),
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

/// The ticket of an intent published through the intake, from the
/// application's threads (`CellIntentTicket`): it shares the intent's
/// state with the strategy, and dropping it withdraws the intent. `C` is
/// what this endpoint's reason to close holds.
pub struct CellIntentTicket<C> {
    /// `None` only once it was let go without withdrawing.
    cell: Option<Arc<IntentCell>>,
    zone: Arc<SyncZone<C>>,
}

impl<C> fmt::Debug for CellIntentTicket<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CellIntentTicket")
            .field("state", &self.cell.as_ref().map(|cell| cell.state()))
            .finish_non_exhaustive()
    }
}

impl<C> CellIntentTicket<C> {
    fn cell(&self) -> &IntentCell {
        // invariant: only `release` takes the cell, and it takes the
        // ticket by value
        self.cell
            .as_ref()
            .expect("a ticket keeps its cell until it goes")
    }

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

impl<C> IntentTicketState for CellIntentTicket<C> {
    type End = ConnectionClosedError<C>;

    fn state(&self) -> IntentState<ConnectionClosedError<C>> {
        let cell = self.cell();
        match cell.state() {
            WAITING if cell.too_large.load(Ordering::Acquire) => IntentState::WaitingTooLarge,
            WAITING => IntentState::Waiting,
            CONSUMED => IntentState::Consumed,
            WITHDRAWN => IntentState::Withdrawn,
            _ => IntentState::Ended(self.ended()),
        }
    }
}

/// Resizing a waiting intent tells the planners waiting for content: one
/// whose room it now fits is woken.
impl<C> IntentTicketResize for CellIntentTicket<C> {
    fn resize(&mut self, min: MinimumLengths) {
        let cell = self.cell();
        cell.resize(min);
        if cell.is_waiting() {
            self.zone.content_changed(ContentChange::Needs {
                class: cell.class,
                need: min.as_last,
            });
        }
    }
}

/// Withdrawing and consuming are ordered by the intent's state: only one
/// of them takes place. A withdrawal that takes place leaves the intent out
/// of every plan made after it; one that comes after the plan that wrote
/// the intent ended reports it consumed. Whether a supply under way writes
/// the intent is its frame source's.
impl<C> IntentTicketWithdraw for CellIntentTicket<C> {
    type Report = IntentWithdrawReport<ConnectionClosedError<C>>;

    fn withdraw(self) -> Self::Report {
        let cell = self.cell();
        if cell.leave_waiting(WITHDRAWN) {
            self.zone.content_changed(ContentChange::Withdrawn);
            return IntentWithdrawReport::Withdrawn;
        }
        // The intent left waiting, and only this ticket withdraws it: it
        // was consumed or it ended.
        match cell.state() {
            CONSUMED => IntentWithdrawReport::Consumed,
            _ => IntentWithdrawReport::Ended(self.ended()),
        }
    }
}

/// The plan that wrote the intent consumes it: the ticket goes without
/// touching the zone.
impl<C> IntentTicketRelease for CellIntentTicket<C> {
    fn release(mut self) {
        self.cell = None;
    }
}

impl<C> Drop for CellIntentTicket<C> {
    fn drop(&mut self) {
        if let Some(cell) = &self.cell
            && cell.leave_waiting(WITHDRAWN)
        {
            self.zone.content_changed(ContentChange::Withdrawn);
        }
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
    /// Whether the link path takes intents for any active link path: its
    /// role, as the planner was last told.
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
    fn new(serial: u64, accepts: bool) -> Self {
        Self {
            serial,
            waker: None,
            accepts,
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

/// How content changed outside the core.
#[derive(Debug, Clone, Copy)]
enum ContentChange {
    /// Content of `class` needing at least `need` bytes was published or
    /// resized.
    Needs { class: FlightClass, need: usize },
    /// A waiting intent was withdrawn.
    Withdrawn,
}

/// What the core shares with its intake and the intake's tickets, once
/// asked for an intake: the reason the connection closed, and what each
/// link path's planner needs to be woken from the application's threads.
#[derive(Debug)]
struct SyncZone<C> {
    closed: OnceLock<CloseReason<C>>,
    waits: Mutex<Waits>,
}

impl<C> SyncZone<C> {
    fn new(link_paths: Vec<LinkPathWait>) -> Arc<Self> {
        Arc::new(Self {
            closed: OnceLock::new(),
            waits: Mutex::new(Waits {
                changes: 0,
                link_paths,
            }),
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
                if wait.change_wakes(change) {
                    woken.extend(wait.waker.take());
                }
            }
        }
        for waker in woken {
            waker.wake();
        }
    }
}

impl LinkPathWait {
    /// Whether `change` may let the waiting link path send: content that
    /// fits its room, or a withdrawal while it left content that did not
    /// fit; content that does not fit is kept as a threshold.
    fn change_wakes(&mut self, change: ContentChange) -> bool {
        match change {
            ContentChange::Needs { class, need } => {
                let fits = self.room.is_some_and(|room| room.fits(class, need));
                if !fits {
                    self.unplanned.add(class, need);
                }
                fits
            }
            ContentChange::Withdrawn => self.blocked,
        }
    }
}

// ---- the publisher ----

/// A change published through `&mut` that the core has not taken in yet.
#[derive(Debug)]
enum KeyChange<J> {
    Publish {
        key: u64,
        intent: J,
        min: MinimumLengths,
        class: FlightClass,
    },
    Resize {
        key: u64,
        min: MinimumLengths,
    },
    Withdraw {
        key: u64,
    },
}

/// What a link path's planner left with the publisher, and what the
/// publisher found for it since.
#[derive(Debug)]
struct PublisherWait {
    serial: u64,
    /// Whether the planner waits: it left its room when it last planned,
    /// and has not planned since.
    waiting: bool,
    /// What it left: whether it takes intents for any active link path,
    /// its room, the least room of content published that did not fit it,
    /// and whether it left content that did not fit.
    wait: LinkPathWait,
    /// Whether something taken since may change its plan.
    marked: bool,
}

/// The publisher of the ranked strategy (`RankedSendPublisher`): it takes
/// the intents published through `&mut`, with their resizing and
/// withdrawing, and keeps them for the core to take in when a planner plans
/// next. As it takes each, it compares it with the room each waiting link
/// path left with it, and marks those whose plan it may change: content
/// that fits the room, or a withdrawal while the link path left content
/// that did not fit; content that does not fit is kept as a threshold the
/// link path's room is compared with when it changes.
pub struct RankedSendPublisher<I: SendStrategyTypes> {
    next_key: u64,
    changes: Vec<KeyChange<I::SendIntents>>,
    waits: Vec<PublisherWait>,
    /// The keys of the intents that wait as too large, in order, as the
    /// core last found.
    too_large: Vec<u64>,
    /// Whether a link path was marked since this was last asked.
    plan_change: bool,
}

impl<I: SendStrategyTypes> fmt::Debug for RankedSendPublisher<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RankedSendPublisher")
            .field("changes", &self.changes.len())
            .field("waits", &self.waits)
            .field("too_large", &self.too_large)
            .finish_non_exhaustive()
    }
}

impl<I: SendStrategyTypes> Default for RankedSendPublisher<I> {
    fn default() -> Self {
        Self {
            next_key: 0,
            changes: Vec::new(),
            waits: Vec::new(),
            too_large: Vec::new(),
            plan_change: false,
        }
    }
}

impl<I: SendStrategyTypes> RankedSendPublisher<I> {
    /// Compare `change` with the room of each waiting link path.
    fn compare(&mut self, change: ContentChange) {
        for wait in &mut self.waits {
            if wait.waiting && wait.wait.accepts && wait.wait.change_wakes(change) {
                wait.marked = true;
                self.plan_change = true;
            }
        }
    }

    fn wait_of(&mut self, serial: u64) -> &mut PublisherWait {
        let at = match self.waits.iter().position(|wait| wait.serial == serial) {
            Some(at) => at,
            None => {
                self.waits.push(PublisherWait {
                    serial,
                    waiting: false,
                    wait: LinkPathWait::new(serial, false),
                    marked: false,
                });
                self.waits.len() - 1
            }
        };
        &mut self.waits[at]
    }

    fn pending_publish(&mut self, key: u64) -> Option<usize> {
        self.changes
            .iter()
            .position(|change| matches!(change, KeyChange::Publish { key: k, .. } if *k == key))
    }
}

impl<I: SendStrategyTypes, J: SendIntent> PublishOutcome<J, AnyActiveLinkPath>
    for RankedSendPublisher<I>
{
    type Outcome = KeyIntentTicket;
}

impl<I, J, Idx> PublishTo<J, AnyActiveLinkPath, Idx> for RankedSendPublisher<I>
where
    I: SendStrategyTypes,
    J: SendIntent,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish_to(&mut self, intent: J, _: AnyActiveLinkPath) -> KeyIntentTicket {
        let intent = <I::SendIntents as InjectSendIntent<J, Idx>>::inject(intent);
        let min = I::min_lengths(&intent);
        let class = I::flight_class(&intent);
        let key = self.next_key;
        self.next_key += 1;
        self.changes.push(KeyChange::Publish {
            key,
            intent,
            min,
            class,
        });
        self.compare(ContentChange::Needs {
            class,
            need: min.as_last,
        });
        KeyIntentTicket { key, class }
    }
}

/// Resizing and withdrawing compare as publishing does; an intent
/// withdrawn before the core took it in is forgotten.
impl<I: SendStrategyTypes> IntentTicketChanges<KeyIntentTicket> for RankedSendPublisher<I> {
    fn resize(&mut self, ticket: &mut KeyIntentTicket, min: MinimumLengths) {
        let key = ticket.key;
        match self.pending_publish(key) {
            Some(at) => {
                if let KeyChange::Publish { min: pending, .. } = &mut self.changes[at] {
                    *pending = min;
                }
            }
            None => self.changes.push(KeyChange::Resize { key, min }),
        }
        self.compare(ContentChange::Needs {
            class: ticket.class,
            need: min.as_last,
        });
    }

    fn withdraw(&mut self, ticket: KeyIntentTicket) {
        let key = ticket.key;
        if let Some(at) = self.pending_publish(key) {
            self.changes.remove(at);
            return;
        }
        self.changes.push(KeyChange::Withdraw { key });
        self.compare(ContentChange::Withdrawn);
    }

    fn release_written(&mut self, _: KeyIntentTicket) {}

    fn waits_too_large(&self, ticket: &KeyIntentTicket) -> bool {
        self.too_large.binary_search(&ticket.key).is_ok()
    }
}

/// What a component published, resized and withdrawn through the
/// publisher, as the tests of the components read it
/// (`PublisherChange`).
///
/// Only for tests: compiled with the feature `test-util`.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublisherChange<J> {
    /// An intent was published with the key `key`.
    Published {
        /// The key of its ticket.
        key: u64,
        /// The intent.
        intent: J,
    },
    /// The intent of `key` needs `min` from now on.
    Resized {
        /// The key of its ticket.
        key: u64,
        /// What it needs.
        min: MinimumLengths,
    },
    /// The intent of `key` was withdrawn.
    Withdrawn {
        /// The key of its ticket.
        key: u64,
    },
}

#[cfg(any(test, feature = "test-util"))]
impl<I: SendStrategyTypes> RankedSendPublisher<I> {
    /// What was published, resized and withdrawn since the last call, as
    /// the core would take it in, which it no longer will: a later resize
    /// or withdrawal of what was taken here comes as one of its own.
    ///
    /// Only for tests: compiled with the feature `test-util`.
    pub fn take_changes(&mut self) -> Vec<PublisherChange<I::SendIntents>> {
        self.changes
            .drain(..)
            .map(|change| match change {
                KeyChange::Publish { key, intent, .. } => {
                    PublisherChange::Published { key, intent }
                }
                KeyChange::Resize { key, min } => PublisherChange::Resized { key, min },
                KeyChange::Withdraw { key } => PublisherChange::Withdrawn { key },
            })
            .collect()
    }
}

impl<I: SendStrategyTypes> SendIntentPublisher for RankedSendPublisher<I> {
    fn take_plan_change(&mut self) -> PlanChange {
        if core::mem::take(&mut self.plan_change) {
            PlanChange::Possible
        } else {
            PlanChange::None
        }
    }
}

// ---- the core ----

/// The state of an intent the core took in from the publisher.
#[derive(Debug, Clone, Copy)]
struct Keyed {
    key: u64,
    min: MinimumLengths,
    class: FlightClass,
    /// Cleared once a plan consumed it.
    waiting: bool,
}

/// An intent the core holds, with the state its ticket `S` shares: a key's
/// ([`Keyed`]), or the cell of one published through the intake.
#[derive(Debug)]
struct Entry<J, S> {
    intent: J,
    state: S,
    /// When it was taken in, among the intents of its holder.
    order: u64,
    /// The serials of the active link paths that passed it over last as
    /// too large for them.
    too_large_on: SmallVec<[u64; 1]>,
}

/// An intent published through the intake, not yet taken in by the core.
#[derive(Debug)]
struct Published<J> {
    intent: J,
    cell: Arc<IntentCell>,
}

#[derive(Debug)]
struct LinkPathEntry {
    serial: u64,
    role: LinkPathRoleKind,
}

/// What the core shares once it is asked for an intake.
struct Shared<I: SendStrategyTypes> {
    published: Arc<Mutex<Vec<Published<I::SendIntents>>>>,
    zone: Arc<SyncZone<I::CloseCause>>,
}

/// The core of the ranked strategy, for the composition's types `I`.
pub struct RankedSendStrategy<I: SendStrategyTypes> {
    /// The intents taken in from the publisher, in the order of their keys.
    keyed: Vec<Entry<I::SendIntents, Keyed>>,
    /// The intents taken in from the intake.
    celled: Vec<Entry<I::SendIntents, Arc<IntentCell>>>,
    link_paths: Vec<LinkPathEntry>,
    keys: [bool; 4],
    handshake_confirmed: bool,
    closed: bool,
    next_order: u64,
    next_serial: u64,
    /// `None` until a component asks for an intake.
    shared: Option<Shared<I>>,
}

impl<I: SendStrategyTypes> fmt::Debug for RankedSendStrategy<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RankedSendStrategy")
            .field("keyed", &self.keyed.len())
            .field("celled", &self.celled.len())
            .field("link_paths", &self.link_paths.len())
            .field("keys", &self.keys)
            .field("handshake_confirmed", &self.handshake_confirmed)
            .field("shared", &self.shared.is_some())
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
        | PlannedPacketKind::SettlingProbe => EncryptionLevel::OneRtt,
    }
}

impl<I: SendStrategyTypes> RankedSendStrategy<I> {
    /// A core with no intents, no link paths and no send keys yet, sharing
    /// nothing.
    pub fn new() -> Self {
        Self {
            keyed: Vec::new(),
            celled: Vec::new(),
            link_paths: Vec::new(),
            keys: [false; 4],
            handshake_confirmed: false,
            closed: false,
            next_order: 0,
            next_serial: 0,
            shared: None,
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

    fn take_order(&mut self) -> u64 {
        let order = self.next_order;
        self.next_order += 1;
        order
    }

    fn keyed_at(&self, key: u64) -> Option<usize> {
        self.keyed
            .binary_search_by_key(&key, |entry| entry.state.key)
            .ok()
    }

    /// Take in what was published through the publisher and the intake;
    /// the publisher forgets the waits of link paths that ended.
    fn take_in(&mut self, published: &mut RankedSendPublisher<I>) {
        let link_paths = &self.link_paths;
        published.waits.retain(|wait| {
            link_paths
                .iter()
                .any(|link_path| link_path.serial == wait.serial)
        });
        for change in published.changes.drain(..) {
            if self.closed {
                continue;
            }
            match change {
                KeyChange::Publish {
                    key,
                    intent,
                    min,
                    class,
                } => {
                    let order = self.next_order;
                    self.next_order += 1;
                    self.keyed.push(Entry {
                        intent,
                        state: Keyed {
                            key,
                            min,
                            class,
                            waiting: true,
                        },
                        order,
                        too_large_on: SmallVec::new(),
                    });
                }
                KeyChange::Resize { key, min } => {
                    if let Some(at) = self.keyed_at(key) {
                        self.keyed[at].state.min = min;
                    }
                }
                KeyChange::Withdraw { key } => {
                    if let Some(at) = self.keyed_at(key) {
                        self.keyed.remove(at);
                    }
                }
            }
        }
        let Some(shared) = &self.shared else {
            return;
        };
        let taken: Vec<_> = lock(&shared.published).drain(..).collect();
        for published in taken {
            let order = self.take_order();
            self.celled.push(Entry {
                intent: published.intent,
                state: published.cell,
                order,
                too_large_on: SmallVec::new(),
            });
        }
    }

    /// The link path of `serial` planned: the intents it passed over as
    /// too large for it are `too_large`, and the others it does not hold
    /// so; an intent too large for every active link path, while there is
    /// one, waits as too large, and the publisher and the cells say so.
    fn found_too_large(
        &mut self,
        serial: u64,
        too_large: &[Held],
        published: &mut RankedSendPublisher<I>,
    ) {
        for entry in &mut self.keyed {
            entry.too_large_on.retain(|on| *on != serial);
        }
        for entry in &mut self.celled {
            entry.too_large_on.retain(|on| *on != serial);
        }
        for held in too_large {
            match *held {
                Held::Keyed(at) => self.keyed[at].too_large_on.push(serial),
                Held::Cell(at) => self.celled[at].too_large_on.push(serial),
                Held::Driver(_) => {}
            }
        }
        let active: SmallVec<[u64; 2]> = self
            .link_paths
            .iter()
            .filter(|link_path| link_path.role == LinkPathRoleKind::Active)
            .map(|link_path| link_path.serial)
            .collect();
        let too_large_everywhere =
            |on: &[u64]| !active.is_empty() && active.iter().all(|serial| on.contains(serial));
        published.too_large.clear();
        published.too_large.extend(
            self.keyed
                .iter()
                .filter(|entry| too_large_everywhere(&entry.too_large_on))
                .map(|entry| entry.state.key),
        );
        for entry in &self.celled {
            entry
                .state
                .too_large
                .store(too_large_everywhere(&entry.too_large_on), Ordering::Release);
        }
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

/// Every intent published through the intake gives back its ticket: the
/// application's content is read and withdrawn by its holder.
impl<I: SendStrategyTypes, J: SendIntent> PublishOutcome<J, AnyActiveLinkPath>
    for RankedSendIntake<I>
{
    type Outcome = CellIntentTicket<I::CloseCause>;
}

impl<I, J, Idx> SharedPublishTo<J, AnyActiveLinkPath, Idx> for RankedSendIntake<I>
where
    I: SendStrategyTypes,
    J: SendIntent,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish_to(&self, intent: J, _: AnyActiveLinkPath) -> CellIntentTicket<I::CloseCause> {
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
        CellIntentTicket {
            cell: Some(cell),
            zone: Arc::clone(&self.zone),
        }
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
    type Publisher = RankedSendPublisher<I>;

    fn add_link_path(
        &mut self,
        _: I::LinkPathIdentifier,
        role: LinkPathRoleKind,
    ) -> Self::LinkPathSendPlanner {
        let serial = self.next_serial;
        self.next_serial += 1;
        self.link_paths.push(LinkPathEntry { serial, role });
        if let Some(shared) = &self.shared {
            lock(&shared.zone.waits)
                .link_paths
                .push(LinkPathWait::new(serial, role == LinkPathRoleKind::Active));
        }
        RankedLinkPathSendPlanner {
            serial,
            zone: None,
            role,
            limits: None,
            overheads: PacketOverheads::default(),
            thresholds: Thresholds::default(),
            turns: [None; URGENCIES],
            close_resends: CloseResends::default(),
            types: PhantomData,
        }
    }

    fn send_keys_available(&mut self, level: EncryptionLevel) -> PlanChange {
        let index = level_index(level);
        if self.keys[index] {
            return PlanChange::None;
        }
        self.keys[index] = true;
        PlanChange::Possible
    }

    fn handshake_confirmed(&mut self) -> PlanChange {
        if self.handshake_confirmed {
            return PlanChange::None;
        }
        self.handshake_confirmed = true;
        PlanChange::Possible
    }

    fn no_more_active_link_paths(&mut self, reason: CloseReason<I::CloseCause>) {
        self.closed = true;
        self.keyed.clear();
        for entry in self.celled.drain(..) {
            entry.state.leave_waiting(ENDED);
        }
        if let Some(shared) = &self.shared {
            let _ = shared.zone.closed.set(reason);
            for published in lock(&shared.published).drain(..) {
                published.cell.leave_waiting(ENDED);
            }
        }
    }
}

/// The zone is made when the first component asks for the intake: the
/// planners of the link paths there then wait in it too, from their
/// next plan on.
impl<I> SharedSendStrategy<I> for RankedSendStrategy<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
    I::LinkPathIdentifier: Clone + PartialEq,
{
    type Intake = RankedSendIntake<I>;

    fn intake(&mut self) -> RankedSendIntake<I> {
        let link_paths = &self.link_paths;
        let shared = self.shared.get_or_insert_with(|| Shared {
            published: Arc::new(Mutex::new(Vec::new())),
            zone: SyncZone::new(
                link_paths
                    .iter()
                    .map(|link_path| {
                        LinkPathWait::new(
                            link_path.serial,
                            link_path.role == LinkPathRoleKind::Active,
                        )
                    })
                    .collect(),
            ),
        });
        RankedSendIntake {
            published: Arc::clone(&shared.published),
            zone: Arc::clone(&shared.zone),
        }
    }
}

// ---- the planner ----

/// The least room blocked content needs, for each flight class, and the
/// least size of a blocked path MTU probe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Thresholds {
    stream_waits_for_pacing: bool,
    ack_only: Option<usize>,
    in_flight: Option<usize>,
    pmtu_probe: Option<usize>,
}

fn add_least(slot: &mut Option<usize>, need: usize) {
    *slot = Some(slot.map_or(need, |least| least.min(need)));
}

impl Thresholds {
    fn add(&mut self, class: FlightClass, need: usize) {
        let slot = match class {
            FlightClass::AckOnly => &mut self.ack_only,
            FlightClass::InFlight => &mut self.in_flight,
        };
        add_least(slot, need);
    }

    fn add_pmtu_probe(&mut self, size: usize) {
        add_least(&mut self.pmtu_probe, size);
    }

    fn is_empty(&self) -> bool {
        !self.stream_waits_for_pacing
            && self.ack_only.is_none()
            && self.in_flight.is_none()
            && self.pmtu_probe.is_none()
    }

    fn reached_by(&self, limits: &DatagramLimits) -> bool {
        (self.stream_waits_for_pacing && !pacing_limits_stream(limits))
            || self
                .ack_only
                .is_some_and(|need| limits.capacity_for(FlightClass::AckOnly) >= need)
            || self
                .in_flight
                .is_some_and(|need| limits.capacity_for(FlightClass::InFlight) >= need)
            || self
                .pmtu_probe
                .is_some_and(|size| limits.pmtu_probe_capacity() >= size)
    }
}

/// Waiting for the pacer can remove a cap that only pacing imposes.
fn pacing_limits_stream(limits: &DatagramLimits) -> bool {
    limits.pacing_release_pending
        && limits.probe_permits == 0
        && limits.pacing_allowance
            < limits
                .capacity_for(FlightClass::AckOnly)
                .min(limits.congestion_window_left)
}

/// When a closing link path sends its close packet again: how many
/// datagrams it had received since the close packet was sealed when it last
/// sent it again; `None` before the first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CloseResends {
    sent_at: Option<u64>,
}

impl CloseResends {
    /// Whether the close packet goes again, as `facts` tell: once it is
    /// sealed, and then when the count of the datagrams received reaches a
    /// power of two above the count at the last resend. A count below that
    /// one is of a close packet sealed again: it goes as one just sealed.
    fn due(&self, facts: CloseResendFacts) -> bool {
        let received = facts.datagrams_received;
        match self.sent_at {
            None => true,
            Some(sent) if received < sent => true,
            Some(0) => received >= 1,
            Some(sent) => received >= sent.saturating_add(1).next_power_of_two(),
        }
    }

    /// The close packet went again, with `facts` as they were.
    fn sent(&mut self, facts: CloseResendFacts) {
        self.sent_at = Some(facts.datagrams_received);
    }
}

/// How many urgencies there are: `0` to `7`.
const URGENCIES: usize = 8;

/// Where an intent stands among the intents of one rank, level and urgency
/// when turns do not change it: the driver's content first, in the order it
/// was gathered, then the core's, in the order they were taken in.
type IntentOrder = (u8, u64);

fn intent_order(held: Held, order: u64) -> IntentOrder {
    match held {
        Held::Driver(_) => (0, order),
        Held::Keyed(_) | Held::Cell(_) => (1, order),
    }
}

/// The planner of one link path in the ranked strategy.
pub struct RankedLinkPathSendPlanner<I: SendStrategyTypes> {
    serial: u64,
    /// The zone of the core's intake, once there is one and the planner
    /// planned since.
    zone: Option<Arc<SyncZone<I::CloseCause>>>,
    role: LinkPathRoleKind,
    limits: Option<DatagramLimits>,
    overheads: PacketOverheads,
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
            .field("close_resends", &self.close_resends)
            .finish_non_exhaustive()
    }
}

impl<I: SendStrategyTypes> RankedLinkPathSendPlanner<I> {
    /// Begin to plan: what was published through the publisher and the
    /// intake is taken in, and the link path no longer waits with either;
    /// the count of changes in the zone before it was taken in, if there
    /// is a zone.
    fn begin(
        &mut self,
        core: &mut RankedSendStrategy<I>,
        published: &mut RankedSendPublisher<I>,
    ) -> Option<u64> {
        if self.zone.is_none() {
            self.zone = core.shared.as_ref().map(|shared| Arc::clone(&shared.zone));
        }
        let wait = published.wait_of(self.serial);
        wait.waiting = false;
        wait.marked = false;
        let changes = self.zone.as_ref().map(|zone| {
            let mut waits = lock(&zone.waits);
            if let Some(wait) = waits
                .link_paths
                .iter_mut()
                .find(|wait| wait.serial == self.serial)
            {
                wait.waker = None;
            }
            waits.changes
        });
        core.take_in(published);
        changes
    }

    /// What this link path leaves where it waits: whether it takes intents
    /// for any active link path, its room, no content that did not fit yet,
    /// and whether something blocks it.
    fn leave(&self, wait: &mut LinkPathWait, blocked: bool) {
        wait.accepts = self.role == LinkPathRoleKind::Active;
        wait.room = self.limits.as_ref().map(Room::of);
        wait.unplanned = Thresholds::default();
        wait.blocked = blocked;
    }

    /// Wait, leaving with the publisher what wakes this link path, and in
    /// the zone, if there is one, with `waker`, unless the zone changed
    /// since the count `seen`: then plan again. `blocked` when something
    /// blocks the link path, so that a withdrawal may let it send: content
    /// that did not fit, or a plan given out that may not be filled.
    fn wait(
        &self,
        published: &mut RankedSendPublisher<I>,
        seen: Option<u64>,
        waker: &Waker,
        blocked: bool,
    ) -> bool {
        if let (Some(zone), Some(seen)) = (&self.zone, seen) {
            let waker = waker.clone();
            let mut waits = lock(&zone.waits);
            if waits.changes != seen {
                return false;
            }
            if let Some(wait) = waits
                .link_paths
                .iter_mut()
                .find(|wait| wait.serial == self.serial)
            {
                wait.waker = Some(waker);
                self.leave(wait, blocked);
            }
        }
        let wait = published.wait_of(self.serial);
        wait.waiting = true;
        wait.marked = false;
        self.leave(&mut wait.wait, blocked);
        true
    }

    /// The link path is told `limits`: its room in the zone follows, and
    /// whether content published there meanwhile now fits.
    fn zone_content_fits(&self, limits: &DatagramLimits) -> bool {
        let Some(zone) = &self.zone else {
            return false;
        };
        let mut waits = lock(&zone.waits);
        let Some(wait) = waits
            .link_paths
            .iter_mut()
            .find(|wait| wait.serial == self.serial)
        else {
            return false;
        };
        wait.room = Some(Room::of(limits));
        wait.waker.is_some() && wait.unplanned.reached_by(limits)
    }
}

/// Limits that reach a threshold the planner keeps may change its plan, as
/// may content published in the zone meanwhile that the new room fits;
/// content published through the publisher is the publisher's to compare
/// ([`LinkPathSendPlanner::intents_changed`]).
impl<I: SendStrategyTypes> Observe<DatagramLimits> for RankedLinkPathSendPlanner<I> {
    fn observe(&mut self, limits: DatagramLimits) -> PlanChange {
        if self.limits == Some(limits) {
            return PlanChange::None;
        }
        self.limits = Some(limits);
        // both are asked: the room in the zone follows the limits
        let zone_fits = self.zone_content_fits(&limits);
        if self.thresholds.reached_by(&limits) || zone_fits {
            PlanChange::Possible
        } else {
            PlanChange::None
        }
    }
}

impl<I: SendStrategyTypes> Observe<PacketOverheads> for RankedLinkPathSendPlanner<I> {
    fn observe(&mut self, overheads: PacketOverheads) -> PlanChange {
        if self.overheads == overheads {
            return PlanChange::None;
        }
        self.overheads = overheads;
        PlanChange::Possible
    }
}

/// Where a planned intent is held: among the core's intents taken in from
/// the publisher or from the intake, or among the driver's content of the
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Keyed(usize),
    Cell(usize),
    Driver(usize),
}

#[derive(Debug, Clone, Copy)]
struct PlannedEntry {
    held: Held,
    /// This STREAM can follow content already written to the datagram.
    needs_companion: bool,
    min: MinimumLengths,
    class: FlightClass,
    /// Whether it holds its place when it writes nothing
    /// ([`SendRank::holds_place`]).
    holds_place: bool,
    /// For application data: its urgency and where it stands, to give the
    /// next turn after it once it is supplied.
    turn: Option<(usize, IntentOrder)>,
    /// Whether the intent stays after a supply that wrote something
    /// ([`RankedIntent::stays_after_writing`]).
    stays: bool,
}

/// The items planned for one datagram, packet after packet: usually one or
/// two, inline, as the plan moves whole from the planner to the filling;
/// more go to the heap.
type PlannedEntries = SmallVec<[PlannedEntry; 2]>;

/// The core's intents a plan passed over as too large for the link path:
/// usually none or one, inline.
type TooLarge = SmallVec<[Held; 1]>;

/// The packets planned for one datagram: at most one of each packet number
/// space, so at most three, inline.
type PacketPlans = SmallVec<[PacketPlan; 3]>;

/// One packet of a datagram's plan: its kind and where its items lie among
/// the datagram's.
#[derive(Debug, Clone, Copy)]
struct PacketPlan {
    kind: PlannedPacketKind,
    start: usize,
    end: usize,
}

impl PacketPlan {
    /// The next eligible item in rank order, counted from the packet's
    /// first, among the datagram's `items`. If the datagram is still empty,
    /// a deferred STREAM gives the next independent source the opportunity
    /// to open it.
    fn next_item(&self, items: &[PlannedEntry], from: usize, has_content: bool) -> Option<usize> {
        let items = &items[self.start..self.end];
        let first = items.get(from)?;
        if has_content || !first.needs_companion {
            return Some(from);
        }
        items[from + 1..]
            .iter()
            .position(|item| !item.needs_companion)
            .map(|offset| from + 1 + offset)
    }
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
        LinkPathRoleKind::Settling => &[PlannedPacketKind::SettlingProbe],
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
        PlannedPacketKind::SettlingProbe => I::SettlingFrameSources::item(intent).is_some(),
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
    intent: &'e J,
    min: MinimumLengths,
    class: FlightClass,
    /// The size of the datagram of a path MTU probe.
    exact: Option<usize>,
}

impl<I> RankedLinkPathSendPlanner<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
{
    /// The packets of the next datagram, from the core's intents and the
    /// driver's content `driver`, the thresholds of what does not fit, and
    /// the core's application data passed over as larger than any datagram
    /// of the link path while it carries 1200 bytes.
    fn plan_packets(
        &self,
        core: &RankedSendStrategy<I>,
        driver: &DriverContent<I::SendIntents>,
    ) -> (PacketPlans, PlannedEntries, Thresholds, TooLarge) {
        let mut thresholds = Thresholds::default();
        let mut too_large = TooLarge::new();
        let Some(limits) = self.limits else {
            return (
                PacketPlans::new(),
                PlannedEntries::new(),
                thresholds,
                too_large,
            );
        };
        let (keyed, celled) = if self.role == LinkPathRoleKind::Active {
            (core.keyed.as_slice(), core.celled.as_slice())
        } else {
            (&[][..], &[][..])
        };
        // usually one or two, inline; more go to the heap
        let mut candidates: SmallVec<[Candidate<'_, _>; 2]> = SmallVec::new();
        let held = driver
            .intents
            .iter()
            .enumerate()
            .map(|(index, intent)| {
                (
                    Held::Driver(index),
                    index as u64,
                    intent,
                    I::min_lengths(intent),
                    I::flight_class(intent),
                )
            })
            .chain(
                keyed
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| entry.state.waiting)
                    .map(|(index, entry)| {
                        (
                            Held::Keyed(index),
                            entry.order,
                            &entry.intent,
                            entry.state.min,
                            entry.state.class,
                        )
                    }),
            )
            .chain(
                celled
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| entry.state.is_waiting())
                    .map(|(index, entry)| {
                        (
                            Held::Cell(index),
                            entry.order,
                            &entry.intent,
                            entry.state.min(),
                            entry.state.class,
                        )
                    }),
            );
        for (held, order, intent, min, class) in held {
            let Some(&kind) = kinds_of(self.role)
                .iter()
                .find(|&&kind| core.can_send(kind) && carries::<I>(kind, intent))
            else {
                continue;
            };
            let rank = intent.rank();
            let exact = (rank.priority == SendPriority::PathMtuProbe)
                .then(|| intent.exact_datagram_size())
                .flatten();
            let order = intent_order(held, order);
            let (urgency, had_turn) = if rank.priority == SendPriority::ApplicationData {
                let urgency = usize::from(intent.urgency().get());
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
                intent,
                min,
                class,
                exact,
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

        let pace_stream = pacing_limits_stream(&limits);
        let mut packets = PacketPlans::new();
        let mut items = PlannedEntries::new();
        // content that only rides along, planned once the rest is
        let mut riders: SmallVec<[(PlannedPacketKind, PlannedEntry); 1]> = SmallVec::new();
        let mut highest: Option<EncryptionLevel> = None;
        for candidate in candidates {
            let Candidate {
                rank,
                level,
                urgency,
                order,
                held,
                kind,
                intent,
                min,
                class,
                exact,
                ..
            } = candidate;
            if I::only_piggybacks(intent) {
                // it opens no packet and leaves no threshold: it goes into a
                // packet of its kind the rest of the plan has, if any
                riders.push((
                    kind,
                    PlannedEntry {
                        held,
                        needs_companion: true,
                        min,
                        class,
                        holds_place: false,
                        turn: None,
                        stays: intent.stays_after_writing(),
                    },
                ));
                continue;
            }
            if highest.is_some_and(|highest| level < highest) {
                break;
            }
            // a kind of packet the link path cannot send now: no room
            // lets it go, so it holds no place and leaves no threshold
            let Some(overhead) = self.overheads.of(kind) else {
                continue;
            };
            if let Some(size) = exact {
                // a path MTU probe leads a datagram of its own: after other
                // content it waits for the next datagram, and it is planned
                // only when its whole size can go now; nothing follows it
                if !packets.is_empty() || size < overhead + min.as_last {
                    continue;
                }
                if size > limits.pmtu_probe_capacity() {
                    thresholds.add_pmtu_probe(size);
                    if rank.holds_place {
                        break;
                    }
                    continue;
                }
                items.push(PlannedEntry {
                    held,
                    needs_companion: false,
                    min,
                    class,
                    holds_place: rank.holds_place,
                    turn: None,
                    stays: intent.stays_after_writing(),
                });
                packets.push(PacketPlan {
                    kind,
                    start: 0,
                    end: 1,
                });
                break;
            }
            let mut class_of_datagram = class;
            let mut need = overhead + min.as_last;
            if kind == PlannedPacketKind::Initial
                && (self.overheads.expands_every_initial || class == FlightClass::InFlight)
            {
                need = need.max(DatagramLimits::MINIMUM);
                class_of_datagram = FlightClass::InFlight;
            }
            let application_data = rank.priority == SendPriority::ApplicationData;
            // what does not fit an empty datagram is not planned; what does
            // is the writing's to fit
            if need > limits.capacity_for(class_of_datagram) {
                thresholds.add(class_of_datagram, need);
                // larger than any datagram of the link path, not only than
                // what its windows allow now
                if application_data
                    && !matches!(held, Held::Driver(_))
                    && limits.supports_minimum()
                    && need > limits.max_udp_payload()
                {
                    too_large.push(held);
                }
                // application data that does not fit is passed over, and
                // so is all content while the link path does not carry
                // 1200 bytes: a datagram size probe may still go
                if rank.holds_place && !application_data && limits.supports_minimum() {
                    break;
                }
                continue;
            }
            highest = Some(level);
            let planned = PlannedEntry {
                held,
                needs_companion: pace_stream
                    && kind == PlannedPacketKind::OneRtt
                    && intent.is_stream(),
                min,
                class,
                holds_place: rank.holds_place,
                turn: application_data.then_some((urgency, order)),
                stays: intent.stays_after_writing(),
            };
            thresholds.stream_waits_for_pacing |= planned.needs_companion;
            items.push(planned);
            match packets.last_mut() {
                Some(packet) if packet.kind == kind => packet.end = items.len(),
                _ => packets.push(PacketPlan {
                    kind,
                    start: items.len() - 1,
                    end: items.len(),
                }),
            }
        }
        if pace_stream {
            let skipped = packets
                .iter()
                .take_while(|p| p.next_item(&items, 0, false).is_none())
                .count();
            if skipped > 0 {
                let gone = packets[skipped - 1].end;
                packets.drain(..skipped);
                items.drain(..gone);
                for packet in &mut packets {
                    packet.start -= gone;
                    packet.end -= gone;
                }
            }
        }
        // what rides along goes first in a packet of its kind that the plan
        // has; it opens none, so a datagram without other content in such
        // a packet does not carry it
        for (kind, rider) in riders {
            let Some(at) = packets.iter().position(|packet| packet.kind == kind) else {
                continue;
            };
            items.insert(packets[at].start, rider);
            packets[at].end += 1;
            for packet in &mut packets[at + 1..] {
                packet.start += 1;
                packet.end += 1;
            }
        }
        (packets, items, thresholds, too_large)
    }
}

impl<I> LinkPathSendPlanner<I> for RankedLinkPathSendPlanner<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
    I::LinkPathIdentifier: Clone + PartialEq,
{
    type Core = RankedSendStrategy<I>;
    type Publisher = RankedSendPublisher<I>;
    type Plan<'a>
        = RankedPlan<'a, I>
    where
        Self: 'a;

    fn poll_plan<'a>(
        &'a mut self,
        core: &'a mut Self::Core,
        published: &mut Self::Publisher,
        driver: &'a DriverContent<I::SendIntents>,
        cx: &mut Context<'_>,
    ) -> Poll<PlannedDatagram<Self::Plan<'a>>> {
        if self.role == LinkPathRoleKind::Closing {
            if let Some(facts) = driver.close
                && self.close_resends.due(facts)
            {
                self.close_resends.sent(facts);
                return Poll::Ready(PlannedDatagram::ResendClose);
            }
            return Poll::Pending;
        }
        loop {
            let seen = self.begin(core, published);
            core.keyed.retain(|entry| entry.state.waiting);
            core.celled.retain(|entry| entry.state.is_waiting());
            let (packets, items, thresholds, too_large) = self.plan_packets(core, driver);
            if self.role == LinkPathRoleKind::Active {
                core.found_too_large(self.serial, &too_large, published);
            }
            if !packets.is_empty() {
                // A companion can disappear or supply zero. The sender then
                // waits without polling for a new plan: the pacing wake
                // stays armed, and what is published or withdrawn from now
                // on wakes it as it wakes a waiting planner.
                self.thresholds = Thresholds {
                    stream_waits_for_pacing: thresholds.stream_waits_for_pacing,
                    ..Thresholds::default()
                };
                if let Some(zone) = &self.zone {
                    let mut waits = lock(&zone.waits);
                    if let Some(wait) = waits
                        .link_paths
                        .iter_mut()
                        .find(|wait| wait.serial == self.serial)
                    {
                        wait.waker = Some(cx.waker().clone());
                        self.leave(wait, true);
                    }
                }
                let wait = published.wait_of(self.serial);
                wait.waiting = true;
                self.leave(&mut wait.wait, true);
                return Poll::Ready(PlannedDatagram::Fill(RankedPlan {
                    core,
                    planner: self,
                    driver,
                    packets,
                    items,
                    next_packet: 0,
                    feedback: RankedFeedback::default(),
                }));
            }
            let blocked = !thresholds.is_empty();
            self.thresholds = thresholds;
            if self.wait(published, seen, cx.waker(), blocked) {
                return Poll::Pending;
            }
        }
    }

    /// The planner's mark is taken, and its room with the publisher follows
    /// its limits; content published that did not fit its room may fit now.
    fn intents_changed(&mut self, published: &mut Self::Publisher) -> PlanChange {
        let limits = self.limits;
        let accepts = self.role == LinkPathRoleKind::Active;
        let wait = published.wait_of(self.serial);
        let marked = core::mem::take(&mut wait.marked);
        wait.wait.accepts = accepts;
        wait.wait.room = limits.as_ref().map(Room::of);
        let reached = wait.waiting
            && limits
                .as_ref()
                .is_some_and(|limits| wait.wait.unplanned.reached_by(limits));
        if marked || reached {
            PlanChange::Possible
        } else {
            PlanChange::None
        }
    }

    /// The planner holds no intents of its own: nothing ends with a role.
    /// Whether the link path takes intents for any active link path follows
    /// the role in the core and in the zone.
    fn role_changed(
        &mut self,
        core: &mut Self::Core,
        role: LinkPathRoleKind,
        _: &mut impl Extend<I::SendIntents>,
    ) -> PlanChange {
        if self.role == role {
            return PlanChange::None;
        }
        self.role = role;
        if role == LinkPathRoleKind::Draining {
            self.close_resends = CloseResends::default();
        }
        if let Some(entry) = core
            .link_paths
            .iter_mut()
            .find(|entry| entry.serial == self.serial)
        {
            entry.role = role;
        }
        if let Some(shared) = &core.shared
            && let Some(wait) = lock(&shared.zone.waits)
                .link_paths
                .iter_mut()
                .find(|wait| wait.serial == self.serial)
        {
            wait.accepts = role == LinkPathRoleKind::Active;
        }
        PlanChange::Possible
    }

    /// The planner holds no intents of its own: nothing ends with it.
    fn ended(self, core: &mut Self::Core, _: &mut impl Extend<I::SendIntents>) {
        core.link_paths.retain(|entry| entry.serial != self.serial);
        if let Some(shared) = &core.shared {
            lock(&shared.zone.waits)
                .link_paths
                .retain(|wait| wait.serial != self.serial);
        }
    }
}

// ---- the plan ----

/// What the ranked plan learns from each supply.
#[derive(Debug, Default)]
pub struct RankedFeedback {
    /// Where the item a cursor gave out and that is not yet supplied lies
    /// among the plan's items.
    current: Option<usize>,
    /// At least one source has written to this datagram.
    has_content: bool,
    /// Where the items supplied lie among the plan's, in order, and whether
    /// each wrote anything; usually one or two, inline.
    supplied: SmallVec<[(usize, bool); 2]>,
}

/// The items are consumed once the plan ends, if they wrote anything and
/// do not stay.
impl SupplyFeedback for RankedFeedback {
    fn supplied(&mut self, written: usize) {
        if let Some(current) = self.current.take() {
            self.has_content |= written > 0;
            self.supplied.push((current, written > 0));
        }
    }
}

/// The plan of one datagram in the ranked strategy.
pub struct RankedPlan<'a, I: SendStrategyTypes> {
    core: &'a mut RankedSendStrategy<I>,
    planner: &'a mut RankedLinkPathSendPlanner<I>,
    driver: &'a DriverContent<I::SendIntents>,
    packets: PacketPlans,
    items: PlannedEntries,
    next_packet: usize,
    feedback: RankedFeedback,
}

impl<I: SendStrategyTypes> fmt::Debug for RankedPlan<'_, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RankedPlan")
            .field("packets", &self.packets)
            .field("items", &self.items)
            .field("next_packet", &self.next_packet)
            .field("feedback", &self.feedback)
            .finish_non_exhaustive()
    }
}

impl<I: SendStrategyTypes> RankedPlan<'_, I> {
    fn intent(&self, held: Held) -> &I::SendIntents {
        held_intent(self.core, self.driver, held)
    }

    fn leading_of(&self, packet: usize) -> Option<LeadingContent<I::FrameSourceId>> {
        let packet = self.packets.get(packet)?;
        let first = &self.items
            [packet.start + packet.next_item(&self.items, 0, self.feedback.has_content)?];
        Some(LeadingContent {
            packet: packet.kind,
            source: I::frame_source(self.intent(first.held)),
            min: first.min,
            class: first.class,
        })
    }
}

/// The intent at `held`, among the core's and the driver's content.
fn held_intent<'e, I: SendStrategyTypes>(
    core: &'e RankedSendStrategy<I>,
    driver: &'e DriverContent<I::SendIntents>,
    held: Held,
) -> &'e I::SendIntents {
    match held {
        Held::Keyed(index) => &core.keyed[index].intent,
        Held::Cell(index) => &core.celled[index].intent,
        Held::Driver(index) => &driver.intents[index],
    }
}

/// The items supplied had their turn; those of the core that wrote
/// anything are consumed, unless they stay after writing, as their sources
/// already resized or withdrew them. The driver's content has no state
/// here: its sources changed their own when they wrote.
impl<I: SendStrategyTypes> Drop for RankedPlan<'_, I> {
    fn drop(&mut self) {
        for (index, wrote) in self.feedback.supplied.drain(..) {
            let entry = self.items[index];
            if let Some((urgency, order)) = entry.turn {
                self.planner.turns[urgency] = Some(order);
            }
            if !wrote || entry.stays {
                continue;
            }
            match entry.held {
                Held::Keyed(index) => self.core.keyed[index].state.waiting = false,
                Held::Cell(index) => {
                    self.core.celled[index].state.leave_waiting(CONSUMED);
                }
                Held::Driver(_) => {}
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
    type SettlingProbe<'p>
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
        if self.next_packet >= self.packets.len() {
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
            PlannedPacketKind::SettlingProbe => {
                PlannedPacket::SettlingProbe(RankedCursor::new(self, packet))
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
        // An item dropped without being supplied wrote nothing: whether the
        // datagram goes on is the filling's, as the item tells it.
        plan.feedback.current = None;
        let packet = plan.packets[self.packet];
        let next = packet.next_item(&plan.items, self.next_item, plan.feedback.has_content)?;
        let items = &mut plan.items[packet.start..packet.end];
        if next > self.next_item {
            items[self.next_item..=next].rotate_right(1);
        }
        let index = packet.start + self.next_item;
        let entry = items[self.next_item];
        self.next_item += 1;
        let last_in_packet = self.next_item == items.len();
        let intent = held_intent(plan.core, plan.driver, entry.held);
        // The packet's kind was chosen because its set carries the intent.
        let item = S::item(intent)?;
        plan.feedback.current = Some(index);
        Some(PlannedItem::new(
            item,
            entry.min,
            entry.class,
            last_in_packet,
            entry.holds_place,
            &mut plan.feedback,
        ))
    }
}

#[cfg(test)]
mod tests;
