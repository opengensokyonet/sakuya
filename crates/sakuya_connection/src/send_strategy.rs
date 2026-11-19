//! The send strategy: where send intents go, in what order, whether they
//! are admitted, and what one datagram carries.
//!
//! Content to send is a send intent ([`SendIntent`]). On the driver's side
//! the strategy is two kinds of values the driver holds and lends to calls:
//! the core ([`SendStrategy`]), in the connection node; and the send
//! planner of each link path ([`LinkPathSendPlanner`]), in the link path's
//! node, which takes the changes of its send conditions ([`Observe`]). The
//! sending call of a link path asks its planner for the plan of the next
//! datagram ([`LinkPathSendPlanner::poll_plan`]); the plan
//! ([`DatagramFillPlan`]) names the packets to write and, in each, the
//! planned items in order; each item reaches its frame source only through
//! [`PlannedItem::supply`], which hands back to the plan how much was
//! written.
//!
//! What the driver's own components have to send is not published: the
//! sending call gathers it for each datagram as it stands then
//! ([`DriverContent`]) and hands it to the planner with the request for the
//! plan; a frame source that writes some of it changes its own state, so
//! the next datagram's gathering no longer has it.
//!
//! Intents of the other components, such as the streams' and the
//! datagrams', are published through `&mut` to the strategy's publisher
//! ([`SendStrategy::Publisher`]), a value the driver holds in the
//! connection node beside the core and lends to whatever publishes: the
//! application's operations through the shared connection, the frames that
//! arrive, the frame sources while a plan has the core. Publishing gives
//! back a ticket that is a key of the strategy's; resizing and withdrawing
//! it go through the publisher too ([`IntentTicketChanges`]). What a
//! publisher took is taken into the core when a planner plans next; the
//! publisher compares it with the room each waiting link path left there
//! as it takes it, and keeps which link paths may plan anew, for the
//! driver to wake ([`SendIntentPublisher::take_plan_change`]).
//!
//! A strategy that also takes intents from the application's threads gives
//! an intake ([`SharedSendStrategy`]) to the components that ask for one
//! when they are built: each holder keeps a handle ([`SendIntentHandle`])
//! for its one kind of intent, and publishing through it
//! ([`SharedPublishTo`]) touches only what the strategy shares for this,
//! never the core; its tickets carry their own state. A component writes
//! its logic once over either ([`IntentPublisher`]).
//!
//! What a strategy may plan is held by structure where it can be: a packet
//! of a kind gets a cursor over that kind's set of frame sources
//! ([`FrameSourceSet`]), so a frame the packet cannot carry has no item to
//! be planned with. Not wasting wake-ups and not missing a send are the
//! strategy's contract.

use core::{
    fmt,
    marker::PhantomData,
    task::{Context, Poll},
};

use sakuya_stream::connection::CloseReason;
use sakuya_wire::{
    parts::{CNil, CoprodInjector, Coproduct, HCons, HNil},
    v1::encryption_level::EncryptionLevel,
};

pub mod ranked;

use crate::write::{
    ClassOfSource, FlightClass, FlightClassType, OpenPacket, PacketWriting, Supplied,
};

// ---- intents and changes of send conditions ----

/// The two least numbers of bytes content needs: as a frame with its
/// Length field, and as the last frame of a packet, where STREAM and
/// DATAGRAM frames leave the Length field out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MinimumLengths {
    /// The least bytes as a frame followed by more frames.
    pub with_length: usize,
    /// The least bytes as the last frame of a packet.
    pub as_last: usize,
}

/// A send intent: content a frame source wants to send.
///
/// What every strategy reads from an intent is given here: which frame
/// source supplies it, how much room it needs at least, and whether it
/// counts in the bytes in flight. What a strategy's own ranking needs is a
/// trait of that strategy, which the parts implement for their intents.
pub trait SendIntent {
    /// The frame sources of the part the intent belongs to.
    type FrameSourceId;
    /// Whether the content counts in the bytes in flight: the class of the
    /// frame source that supplies it.
    type Class: FlightClassType;

    /// The frame source that supplies the intent.
    fn frame_source(&self) -> Self::FrameSourceId;

    /// The least room the intent needs.
    fn min_lengths(&self) -> MinimumLengths;

    /// Whether the content only rides along: it goes only into a packet of
    /// its packet number space that carries other content, in a datagram
    /// sent anyway, and no datagram is sent for it alone. An ACK frame the
    /// obligation wants in a packet sent anyway is such content (RFC 9000
    /// §13.2.1). By default content does not.
    fn only_piggybacks(&self) -> bool {
        false
    }
}

/// A change of the conditions a link path sends under: its windows, the
/// pacer's release, the probe permit, the connection IDs it may use, the
/// anti-amplification credit, the packet number length.
pub trait SendConditionChange {}

/// `R: PublishOutcome<J, D>`: what `R` gives back for an intent `J`
/// published for the destination `D`, wherever `J` is in the composition's
/// sum of intents, such as a ticket for intents someone reads or withdraws.
/// A component that keeps what it gets back names its type by this, without
/// the place of `J`.
pub trait PublishOutcome<J: SendIntent, D> {
    /// What publishing gives back.
    type Outcome;
}

/// `R: SharedPublishTo<J, D, Idx>`: `R` takes intents `J` for the
/// destination `D` through a shared reference. The intake of a strategy
/// ([`SharedSendStrategy::intake`]) implements it for the intents published from
/// the application's threads.
///
/// `Idx` is the place of `J` in the composition's sum of intents; the
/// compiler infers it. What a strategy does differently for each kind of
/// intent belongs to its implementations of this trait: its handles are one
/// type for every kind ([`SendIntentIntake::Handle`]).
pub trait SharedPublishTo<J: SendIntent, D, Idx>: PublishOutcome<J, D> {
    /// Publish `intent` for `destination`.
    fn publish_to(&self, intent: J, destination: D) -> <Self as PublishOutcome<J, D>>::Outcome;
}

/// The intake of a send strategy (`SendIntentIntake`): what publishes
/// intents for the destinations `D` from outside the driver's borrows,
/// cloned to every holder.
///
/// A holder gets a handle for the one kind of intent it publishes; the
/// place `Idx` of that kind stays in the handle's type, inferred where the
/// handle is taken.
pub trait SendIntentIntake<D>: Clone {
    /// The handle that publishes intents `J` at the place `Idx`.
    type Handle<J: SendIntent, Idx>: SendIntentHandle<J, D, Outcome = <Self as PublishOutcome<J, D>>::Outcome>
    where
        Self: SharedPublishTo<J, D, Idx>;

    /// The handle for intents `J`.
    fn handle<J: SendIntent, Idx>(&self) -> Self::Handle<J, Idx>
    where
        Self: SharedPublishTo<J, D, Idx>;
}

/// A handle that publishes intents `J` for the destinations `D`
/// (`SendIntentHandle`), taken from a strategy's intake.
pub trait SendIntentHandle<J: SendIntent, D>: Clone {
    /// What publishing gives back.
    type Outcome;

    /// Publish `intent` for `destination`.
    fn publish_to(&self, intent: J, destination: D) -> Self::Outcome;
}

/// A handle that publishes through a clone of the intake `K`, with the kind
/// of intent `J` and its place `Idx` fixed (`IntakeSendIntentHandle`): the
/// one implementation of [`SendIntentHandle`] an intake needs, whatever it
/// does for each kind.
pub struct IntakeSendIntentHandle<K, J, Idx> {
    intake: K,
    intent: PhantomData<fn(J) -> Idx>,
}

impl<K, J, Idx> IntakeSendIntentHandle<K, J, Idx> {
    /// The handle publishing through `intake`.
    pub fn new(intake: K) -> Self {
        Self {
            intake,
            intent: PhantomData,
        }
    }
}

impl<K: Clone, J, Idx> Clone for IntakeSendIntentHandle<K, J, Idx> {
    fn clone(&self) -> Self {
        Self::new(self.intake.clone())
    }
}

impl<K: fmt::Debug, J, Idx> fmt::Debug for IntakeSendIntentHandle<K, J, Idx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntakeSendIntentHandle")
            .field("intake", &self.intake)
            .finish()
    }
}

impl<K, J, D, Idx> SendIntentHandle<J, D> for IntakeSendIntentHandle<K, J, Idx>
where
    K: SharedPublishTo<J, D, Idx> + Clone,
    J: SendIntent,
{
    type Outcome = <K as PublishOutcome<J, D>>::Outcome;

    fn publish_to(&self, intent: J, destination: D) -> Self::Outcome {
        self.intake.publish_to(intent, destination)
    }
}

/// `R: Observe<J>`: `R` takes the changes `J` of its send conditions.
///
/// It is given the current value; the same value given again is no
/// change.
pub trait Observe<J: SendConditionChange> {
    /// The conditions are now `change`; whether the plan may change.
    fn observe(&mut self, change: J) -> PlanChange;
}

/// Whether what a strategy was told may change a plan (`PlanChange`): the
/// driver wakes the sending calls it may concern, which ask for a plan
/// again.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PlanChange {
    /// No plan changes.
    #[default]
    None,
    /// A plan may change.
    Possible,
}

impl PlanChange {
    /// Whether a plan may change.
    pub fn is_possible(self) -> bool {
        self == Self::Possible
    }

    /// Either may change a plan.
    pub fn or(self, other: Self) -> Self {
        if self.is_possible() { self } else { other }
    }
}

// ---- publishing through `&mut` ----

/// `R: PublishTo<J, D, Idx>`: `R` takes intents `J` for the destination `D`
/// through `&mut`: the publisher of a strategy
/// ([`SendStrategy::Publisher`]). `Idx` is the place of `J` in the
/// composition's sum of intents; the compiler infers it.
pub trait PublishTo<J: SendIntent, D, Idx>: PublishOutcome<J, D> {
    /// Publish `intent` for `destination`.
    fn publish_to(&mut self, intent: J, destination: D) -> <Self as PublishOutcome<J, D>>::Outcome;
}

/// `R: IntentTicketChanges<K>`: `R` resizes and withdraws the intents of its
/// tickets `K`, which are only keys of its, and lets them go once written.
pub trait IntentTicketChanges<K> {
    /// The intent of `ticket` needs at least `min` from now on.
    fn resize(&mut self, ticket: &mut K, min: MinimumLengths);

    /// Withdraw the intent of `ticket`: it is not written into a packet
    /// after this.
    fn withdraw(&mut self, ticket: K);

    /// The frame of `ticket`'s intent was written: the plan that gave it
    /// consumes it, and the ticket goes without withdrawing it.
    fn release_written(&mut self, ticket: K);

    /// Whether the intent of `ticket` waits as too large: none of the
    /// active link paths its destination allows can carry it now.
    fn waits_too_large(&self, ticket: &K) -> bool;
}

/// The publisher of a strategy (`SendIntentPublisher`), as the driver sees
/// it: whether what it took since it was last asked may change the plan of
/// a link path, so that the driver hands that on.
pub trait SendIntentPublisher {
    /// Whether what was published, resized or withdrawn since this was
    /// last asked may change the plan of a waiting link path.
    fn take_plan_change(&mut self) -> PlanChange;
}

/// What a component publishes its intents `J` for the destinations `D`
/// through (`IntentPublisher`): the strategy's publisher with the place of
/// `J` fixed ([`PlacedPublisher`]), or a handle of the strategy's intake
/// ([`IntakeSendIntentHandle`]). A component writes its logic once over it.
pub trait IntentPublisher<J: SendIntent, D> {
    /// What publishing gives back.
    type Ticket;

    /// Publish `intent` for `destination`.
    fn publish_to(&mut self, intent: J, destination: D) -> Self::Ticket;

    /// The intent of `ticket` needs at least `min` from now on.
    fn resize(&mut self, ticket: &mut Self::Ticket, min: MinimumLengths);

    /// Withdraw the intent of `ticket`.
    fn withdraw(&mut self, ticket: Self::Ticket);

    /// The frame of `ticket`'s intent was written: let the ticket go
    /// without withdrawing it, as the plan consumes it.
    fn release_written(&mut self, ticket: Self::Ticket);

    /// Whether the intent of `ticket` waits as too large now.
    fn waits_too_large(&self, ticket: &Self::Ticket) -> bool;
}

/// The publisher `R` of a strategy, borrowed, with the kind of intent `J`
/// and its place `Idx` fixed (`PlacedPublisher`): what a component
/// publishes through when it is lent the publisher.
pub struct PlacedPublisher<'r, R, J, Idx> {
    publisher: &'r mut R,
    intent: PhantomData<fn(J) -> Idx>,
}

impl<'r, R, J, Idx> PlacedPublisher<'r, R, J, Idx> {
    /// Publish through `publisher`.
    pub fn new(publisher: &'r mut R) -> Self {
        Self {
            publisher,
            intent: PhantomData,
        }
    }
}

impl<R, J, Idx> fmt::Debug for PlacedPublisher<'_, R, J, Idx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlacedPublisher").finish_non_exhaustive()
    }
}

impl<R, J, D, Idx> IntentPublisher<J, D> for PlacedPublisher<'_, R, J, Idx>
where
    J: SendIntent,
    R: PublishTo<J, D, Idx> + IntentTicketChanges<<R as PublishOutcome<J, D>>::Outcome>,
{
    type Ticket = <R as PublishOutcome<J, D>>::Outcome;

    fn publish_to(&mut self, intent: J, destination: D) -> Self::Ticket {
        self.publisher.publish_to(intent, destination)
    }

    fn resize(&mut self, ticket: &mut Self::Ticket, min: MinimumLengths) {
        self.publisher.resize(ticket, min);
    }

    fn withdraw(&mut self, ticket: Self::Ticket) {
        self.publisher.withdraw(ticket);
    }

    fn release_written(&mut self, ticket: Self::Ticket) {
        self.publisher.release_written(ticket);
    }

    fn waits_too_large(&self, ticket: &Self::Ticket) -> bool {
        self.publisher.waits_too_large(ticket)
    }
}

/// A handle of the intake publishes as a component's publisher: its tickets
/// resize, withdraw and tell their state themselves.
impl<K, J, D, Idx> IntentPublisher<J, D> for IntakeSendIntentHandle<K, J, Idx>
where
    K: SharedPublishTo<J, D, Idx> + Clone,
    J: SendIntent,
    <K as PublishOutcome<J, D>>::Outcome:
        IntentTicketResize + IntentTicketWithdraw + IntentTicketRelease + IntentTicketState,
{
    type Ticket = <K as PublishOutcome<J, D>>::Outcome;

    fn publish_to(&mut self, intent: J, destination: D) -> Self::Ticket {
        self.intake.publish_to(intent, destination)
    }

    fn resize(&mut self, ticket: &mut Self::Ticket, min: MinimumLengths) {
        ticket.resize(min);
    }

    fn withdraw(&mut self, ticket: Self::Ticket) {
        let _ = ticket.withdraw();
    }

    fn release_written(&mut self, ticket: Self::Ticket) {
        ticket.release();
    }

    fn waits_too_large(&self, ticket: &Self::Ticket) -> bool {
        matches!(ticket.state(), IntentState::WaitingTooLarge)
    }
}

/// The destination of content any active link path may send, defined with
/// the send destinations of `sakuya_stream` because a stream's data is
/// grouped by it; kept here at the path the send strategy has always named
/// it by.
pub use sakuya_stream::send_options::destination::AnyActiveLinkPath;

// ---- the room of a datagram ----

/// What a link path can send in its next new datagram, read afresh from
/// its components when filling starts. The raw quantities are fields; what
/// follows from them are methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramLimits {
    /// What the link takes at most; `None` when asking it failed.
    pub link_ceiling: Option<usize>,
    /// The peer's `max_udp_payload_size`.
    pub peer_max_udp_payload: usize,
    /// What path MTU discovery concluded; 1200 without it.
    pub pmtu_conclusion: usize,
    /// What the anti-amplification limit still allows (RFC 9000 §8.1);
    /// `None` once the peer's address is validated.
    pub anti_amplification_credit: Option<u64>,
    /// What the congestion window still allows in flight.
    pub congestion_window_left: usize,
    /// What the pacer releases now.
    pub pacing_allowance: usize,
    /// Whether the pacer has a next release at which its allowance is revisited.
    pub pacing_release_pending: bool,
    /// How many probe datagrams may still be sent past the congestion
    /// window and pacing (RFC 9002 §6.2.4, §7.5).
    pub probe_permits: u8,
}

impl SendConditionChange for DatagramLimits {}

impl DatagramLimits {
    /// The least size every QUIC path supports (RFC 9000 §14).
    pub const MINIMUM: usize = 1200;

    /// The size datagrams are sent at: the conclusion, within the peer's
    /// limit and the link's ceiling, the ceiling counted as at least 1200;
    /// without the ceiling, the first two.
    pub fn max_udp_payload(&self) -> usize {
        let size = self.pmtu_conclusion.min(self.peer_max_udp_payload);
        match self.link_ceiling {
            Some(ceiling) => size.min(ceiling.max(Self::MINIMUM)),
            None => size,
        }
    }

    /// The largest size a probe may try: the link's ceiling within the
    /// peer's limit; `None` without the ceiling.
    pub fn probe_ceiling(&self) -> Option<usize> {
        self.link_ceiling
            .map(|ceiling| ceiling.min(self.peer_max_udp_payload))
    }

    /// Whether the link path carries 1200 bytes: the link's ceiling is not
    /// below it (counted as carrying when the ceiling is unknown) and the
    /// conclusion is not below it.
    pub fn supports_minimum(&self) -> bool {
        self.link_ceiling
            .is_none_or(|ceiling| ceiling >= Self::MINIMUM)
            && self.pmtu_conclusion >= Self::MINIMUM
    }

    /// The bytes content of `class` may take now in a new datagram; 0 when
    /// the link path does not carry 1200 bytes.
    pub fn capacity_for(&self, class: FlightClass) -> usize {
        if !self.supports_minimum() {
            return 0;
        }
        let any = self.max_udp_payload().min(self.credit());
        match class {
            FlightClass::AckOnly => any,
            FlightClass::InFlight if self.probe_permits > 0 => any,
            FlightClass::InFlight => any
                .min(self.congestion_window_left)
                .min(self.pacing_allowance),
        }
    }

    /// The largest datagram a path MTU probe may be now: within the
    /// [`probe_ceiling`](Self::probe_ceiling), the anti-amplification
    /// credit, the congestion window and pacing, without the permits past
    /// them, whether or not the link path carries 1200 bytes; 0 without the
    /// ceiling. A probe of a size goes when this is not below it.
    pub fn pmtu_probe_capacity(&self) -> usize {
        self.probe_ceiling()
            .unwrap_or(0)
            .min(self.credit())
            .min(self.congestion_window_left)
            .min(self.pacing_allowance)
    }

    /// What the anti-amplification limit allows, as bytes.
    fn credit(&self) -> usize {
        self.anti_amplification_credit.map_or(usize::MAX, |credit| {
            usize::try_from(credit).unwrap_or(usize::MAX)
        })
    }
}

/// The bytes a packet of each kind takes beyond its frames on a link path
/// now: its header with the connection ID it would use and its packet
/// number length, the AEAD tag, and what the header protection sample
/// needs of the payload after a short packet number. `None` for a kind the
/// link path cannot send now. Changes of the connection IDs offered and of
/// packet number lengths reach the strategy as this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacketOverheads {
    /// An Initial packet's.
    pub initial: Option<usize>,
    /// A Handshake packet's.
    pub handshake: Option<usize>,
    /// A 0-RTT packet's.
    pub zero_rtt: Option<usize>,
    /// A 1-RTT packet's.
    pub one_rtt: Option<usize>,
    /// Whether every datagram with an Initial packet is expanded to 1200
    /// bytes, as a client's are; a server expands only those whose Initial
    /// packet elicits an acknowledgment (RFC 9000 §14.1).
    pub expands_every_initial: bool,
}

impl SendConditionChange for PacketOverheads {}

impl PacketOverheads {
    /// The overhead of a packet of `kind`, if the link path can send one.
    pub fn of(&self, kind: PlannedPacketKind) -> Option<usize> {
        match kind {
            PlannedPacketKind::Initial => self.initial,
            PlannedPacketKind::Handshake => self.handshake,
            PlannedPacketKind::ZeroRtt => self.zero_rtt,
            PlannedPacketKind::OneRtt
            | PlannedPacketKind::OneRttProbe
            | PlannedPacketKind::SettlingProbe => self.one_rtt,
        }
    }
}

// ---- the sum of the parts' intents ----

/// The intents of one part, as a sum (a `Coproduct` ending in `CNil`) of
/// intent types that share the part's frame sources.
pub trait PartSendIntents<Id> {
    /// The frame source that supplies the intent.
    fn frame_source(&self) -> Id;
    /// The least room the intent needs.
    fn min_lengths(&self) -> MinimumLengths;
    /// Whether the intent counts in the bytes in flight.
    fn flight_class(&self) -> FlightClass;
    /// Whether the intent only rides along ([`SendIntent::only_piggybacks`]).
    fn only_piggybacks(&self) -> bool;
}

impl<Id> PartSendIntents<Id> for CNil {
    fn frame_source(&self) -> Id {
        match *self {}
    }

    fn min_lengths(&self) -> MinimumLengths {
        match *self {}
    }

    fn flight_class(&self) -> FlightClass {
        match *self {}
    }

    fn only_piggybacks(&self) -> bool {
        match *self {}
    }
}

impl<Id, H, T> PartSendIntents<Id> for Coproduct<H, T>
where
    H: SendIntent<FrameSourceId = Id>,
    T: PartSendIntents<Id>,
{
    fn frame_source(&self) -> Id {
        match self {
            Coproduct::Inl(intent) => intent.frame_source(),
            Coproduct::Inr(rest) => rest.frame_source(),
        }
    }

    fn min_lengths(&self) -> MinimumLengths {
        match self {
            Coproduct::Inl(intent) => intent.min_lengths(),
            Coproduct::Inr(rest) => rest.min_lengths(),
        }
    }

    fn flight_class(&self) -> FlightClass {
        match self {
            Coproduct::Inl(_) => H::Class::FLIGHT_CLASS,
            Coproduct::Inr(rest) => rest.flight_class(),
        }
    }

    fn only_piggybacks(&self) -> bool {
        match self {
            Coproduct::Inl(intent) => intent.only_piggybacks(),
            Coproduct::Inr(rest) => rest.only_piggybacks(),
        }
    }
}

/// What one part sends: its intents and its frame sources. Implemented by
/// the marker type of the part.
pub trait SendIntentPart {
    /// The part's frame sources, as one type.
    type FrameSourceId;
    /// The part's intents: a sum of its intent types; `CNil` when it sends
    /// nothing.
    type SendIntents: PartSendIntents<Self::FrameSourceId> + 'static;
    /// The kinds of the part's frame sources: a list of
    /// [`FrameSourceKind`](crate::frame_source::FrameSourceKind)s, `HNil`
    /// when it writes no frames. The part's items and summaries follow from
    /// it, and so does handing each to its source.
    type FrameSources: crate::frame_source::FrameSourceKinds;

    /// The item of the part's frame sources that `intent` stands for,
    /// whatever kind of packet would carry it: what an intent not fulfilled
    /// is handed back to its frame source as.
    fn intent_item(
        intent: &Self::SendIntents,
    ) -> <Self::FrameSources as crate::frame_source::FrameSourceKinds>::Items<'_>;
}

/// The intents and frame sources of a list of parts: at each part's
/// position, that part's.
pub trait SendIntentsOf {
    /// The frame sources of all parts.
    type FrameSourceIds;
    /// The intents of all parts.
    type SendIntents;

    /// The frame source that supplies `intent`.
    fn frame_source(intent: &Self::SendIntents) -> Self::FrameSourceIds;
    /// The least room `intent` needs.
    fn min_lengths(intent: &Self::SendIntents) -> MinimumLengths;
    /// Whether `intent` counts in the bytes in flight.
    fn flight_class(intent: &Self::SendIntents) -> FlightClass;
    /// Whether `intent` only rides along ([`SendIntent::only_piggybacks`]).
    fn only_piggybacks(intent: &Self::SendIntents) -> bool;
}

impl SendIntentsOf for HNil {
    type FrameSourceIds = CNil;
    type SendIntents = CNil;

    fn frame_source(intent: &CNil) -> CNil {
        match *intent {}
    }

    fn min_lengths(intent: &CNil) -> MinimumLengths {
        match *intent {}
    }

    fn flight_class(intent: &CNil) -> FlightClass {
        match *intent {}
    }

    fn only_piggybacks(intent: &CNil) -> bool {
        match *intent {}
    }
}

impl<P: SendIntentPart, Ps: SendIntentsOf> SendIntentsOf for HCons<P, Ps> {
    type FrameSourceIds = Coproduct<P::FrameSourceId, Ps::FrameSourceIds>;
    type SendIntents = Coproduct<P::SendIntents, Ps::SendIntents>;

    fn frame_source(intent: &Self::SendIntents) -> Self::FrameSourceIds {
        match intent {
            Coproduct::Inl(intent) => Coproduct::Inl(intent.frame_source()),
            Coproduct::Inr(rest) => Coproduct::Inr(Ps::frame_source(rest)),
        }
    }

    fn min_lengths(intent: &Self::SendIntents) -> MinimumLengths {
        match intent {
            Coproduct::Inl(intent) => intent.min_lengths(),
            Coproduct::Inr(rest) => Ps::min_lengths(rest),
        }
    }

    fn flight_class(intent: &Self::SendIntents) -> FlightClass {
        match intent {
            Coproduct::Inl(intent) => intent.flight_class(),
            Coproduct::Inr(rest) => Ps::flight_class(rest),
        }
    }

    fn only_piggybacks(intent: &Self::SendIntents) -> bool {
        match intent {
            Coproduct::Inl(intent) => intent.only_piggybacks(),
            Coproduct::Inr(rest) => Ps::only_piggybacks(rest),
        }
    }
}

/// Putting an intent `J` into a sum of the parts' intents `Self`: into its
/// part's sum, then at that part's position. `Idx` is the pair of places;
/// the compiler infers it.
pub trait InjectSendIntent<J, Idx> {
    /// The sum holding `intent`.
    fn inject(intent: J) -> Self;
}

/// The place of a value, such as an intent or a summary, in the part at
/// the head of a sum of the parts' sums, with `Inner` its place in that
/// part's own sum.
#[derive(Debug)]
pub enum InHead<Inner> {
    #[doc(hidden)]
    _Never(PhantomData<Inner>, core::convert::Infallible),
}

/// The place of a value, such as an intent or a summary, in a later part
/// of a sum of the parts' sums.
#[derive(Debug)]
pub enum InTail<Idx> {
    #[doc(hidden)]
    _Never(PhantomData<Idx>, core::convert::Infallible),
}

impl<J, Head, Tail, Inner> InjectSendIntent<J, InHead<Inner>> for Coproduct<Head, Tail>
where
    Head: CoprodInjector<J, Inner>,
{
    fn inject(intent: J) -> Self {
        Coproduct::Inl(Head::inject(intent))
    }
}

impl<J, Head, Tail, Idx> InjectSendIntent<J, InTail<Idx>> for Coproduct<Head, Tail>
where
    Tail: InjectSendIntent<J, Idx>,
{
    fn inject(intent: J) -> Self {
        Coproduct::Inr(Tail::inject(intent))
    }
}

// ---- the strategy's types ----

/// The kinds of packet a datagram's plan can name, each with its own set
/// of frame sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlannedPacketKind {
    /// An Initial packet.
    Initial,
    /// A Handshake packet.
    Handshake,
    /// A 0-RTT packet.
    ZeroRtt,
    /// A 1-RTT packet of a link path that sends application data.
    OneRtt,
    /// A 1-RTT packet of a candidate link path: probing only.
    OneRttProbe,
    /// A 1-RTT packet of a settling link path: probing only, the
    /// PATH_RESPONSE frames it answers with and the PATH_CHALLENGE frames of
    /// its own path validation (RFC 9000 §9.1, §9.3.3).
    SettlingProbe,
}

/// The types a composition gives every send strategy: the intents, the
/// frame sources, the set of frame sources of each kind of packet, what
/// identifies a link path, and the cause of a close.
pub trait SendStrategyTypes {
    /// The sum of the parts' intents.
    type SendIntents;
    /// The frame sources of all parts; filling dispatches by it.
    type FrameSourceId;
    /// What tells one link path from another.
    type LinkPathIdentifier;
    /// What this endpoint's reason to close holds, as in [`CloseReason`].
    type CloseCause;

    /// The frame sources of an Initial packet.
    type InitialFrameSources: FrameSourceSet<Intents = Self::SendIntents>;
    /// The frame sources of a Handshake packet.
    type HandshakeFrameSources: FrameSourceSet<Intents = Self::SendIntents>;
    /// The frame sources of a 0-RTT packet.
    type ZeroRttFrameSources: FrameSourceSet<Intents = Self::SendIntents>;
    /// The frame sources of a 1-RTT packet.
    type OneRttFrameSources: FrameSourceSet<Intents = Self::SendIntents>;
    /// The frame sources of a 1-RTT packet of a candidate link path.
    type ProbeFrameSources: FrameSourceSet<Intents = Self::SendIntents>;
    /// The frame sources of a 1-RTT packet of a settling link path.
    type SettlingFrameSources: FrameSourceSet<Intents = Self::SendIntents>;

    /// The frame source that supplies `intent`.
    fn frame_source(intent: &Self::SendIntents) -> Self::FrameSourceId;
    /// The least room `intent` needs.
    fn min_lengths(intent: &Self::SendIntents) -> MinimumLengths;
    /// Whether `intent` counts in the bytes in flight.
    fn flight_class(intent: &Self::SendIntents) -> FlightClass;
    /// Whether `intent` only rides along ([`SendIntent::only_piggybacks`]):
    /// a strategy sends no datagram for such content alone. By default
    /// none does.
    fn only_piggybacks(intent: &Self::SendIntents) -> bool {
        let _ = intent;
        false
    }
}

/// What a link path does, as the send strategy sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkPathRoleKind {
    /// Being validated: only probing is sent.
    Candidate,
    /// Sends application data.
    Active,
    /// No longer active: only PATH_RESPONSE is sent.
    Settling,
    /// The connection is closing: only the close packet is sent back.
    Closing,
    /// The connection is draining: nothing is sent.
    Draining,
}

/// The core of a send strategy: held in the connection node; it takes the
/// connection's events. Its publisher ([`Publisher`](Self::Publisher)),
/// beside it in the connection node, takes the intents published through
/// `&mut`; a planner takes them into the core when it plans.
///
/// Dropping the core is the end of all sending.
pub trait SendStrategy<I: SendStrategyTypes>: Sized {
    /// Where an intent may go; what it means is the strategy's. A
    /// component that needs a destination asks for it on its own
    /// `where` clause.
    type Destination;
    /// The send planner of one link path.
    type LinkPathSendPlanner: LinkPathSendPlanner<I, Core = Self, Publisher = Self::Publisher>;
    /// What takes the intents published through `&mut`, made with the core
    /// and held beside it: lent to whatever publishes, also while a plan
    /// has the core.
    type Publisher: SendIntentPublisher + Default;

    /// A link path `id` begins, in `role`: its send planner.
    fn add_link_path(
        &mut self,
        id: I::LinkPathIdentifier,
        role: LinkPathRoleKind,
    ) -> Self::LinkPathSendPlanner;

    /// The keys to send packets at `level` are now in place; whether the
    /// plan of any link path may change.
    fn send_keys_available(&mut self, level: EncryptionLevel) -> PlanChange;

    /// The handshake is confirmed: no more Initial or Handshake packets
    /// are sent; whether the plan of any link path may change.
    fn handshake_confirmed(&mut self) -> PlanChange;

    /// No link path will be active again, for `reason`: intents whose
    /// destination is any active link path end.
    fn no_more_active_link_paths(&mut self, reason: CloseReason<I::CloseCause>);
}

/// A send strategy that also takes intents from the application's threads
/// (`SharedSendStrategy`): it gives an intake to the components that ask
/// for one when they are built, such as a stream set whose capabilities
/// are held apart from the connection. A strategy that is asked for none
/// shares nothing.
pub trait SharedSendStrategy<I: SendStrategyTypes>: SendStrategy<I> {
    /// The intake: intents published through it reach the core without
    /// the core being borrowed, from the application's threads.
    type Intake: SendIntentIntake<Self::Destination>;

    /// The intake of this core.
    fn intake(&mut self) -> Self::Intake;
}

/// The send planner of one link path: held in the link path's node; it
/// takes the changes of its send conditions ([`Observe`]), and plans each
/// datagram from what the intake published and what the driver's own
/// components have to send then ([`DriverContent`]).
pub trait LinkPathSendPlanner<I: SendStrategyTypes>: Sized {
    /// The core it plans with.
    type Core;
    /// The publisher of the core.
    type Publisher;
    /// The plan of one datagram, borrowing the planner and the core.
    type Plan<'a>: DatagramFillPlan<I>
    where
        Self: 'a,
        Self::Core: 'a;

    /// The plan of the next datagram, with `driver` what the driver's own
    /// components have to send on the link path now, once there is one.
    /// What `published` took is taken into the core first; while there is
    /// no plan, the planner leaves there the room of its next datagram, to
    /// be compared with what is published next. The driver keeps the
    /// sending call's waker, and wakes it when what the planner is told,
    /// or its own content, may change the plan; a strategy that shares an
    /// intake keeps a waker of its own for what the intake takes.
    fn poll_plan<'a>(
        &'a mut self,
        core: &'a mut Self::Core,
        published: &mut Self::Publisher,
        driver: &'a DriverContent<I::SendIntents>,
        cx: &mut Context<'_>,
    ) -> Poll<PlannedDatagram<Self::Plan<'a>>>;

    /// What `published` took since the planner last waited, or what the
    /// planner was told since, may change its plan: the planner leaves its
    /// room there as it is now, and tells whether its sending call is to
    /// be woken. The driver asks it when the publisher took something that
    /// may change the plan of a link path, and after telling the planner
    /// anything else.
    fn intents_changed(&mut self, published: &mut Self::Publisher) -> PlanChange;

    /// The link path's role is now `role`; whether the plan may change. The
    /// intents the planner ends for it go to `ended`: the driver hands each
    /// back to its frame source as not fulfilled
    /// ([`Unfulfilled::Ended`](sakuya_stream::send_options::destination::Unfulfilled::Ended)).
    fn role_changed(
        &mut self,
        core: &mut Self::Core,
        role: LinkPathRoleKind,
        ended: &mut impl Extend<I::SendIntents>,
    ) -> PlanChange;

    /// The link path ended. The intents the planner ends with it go to
    /// `ended`, as with [`role_changed`](Self::role_changed).
    fn ended(self, core: &mut Self::Core, ended: &mut impl Extend<I::SendIntents>);
}

// ---- the plan of a datagram ----

/// What [`LinkPathSendPlanner::poll_plan`] gives: a datagram to fill, or
/// the sealed close packet to send again as it is.
#[derive(Debug)]
pub enum PlannedDatagram<F> {
    /// Fill a datagram by the plan.
    Fill(F),
    /// Send the close packet again.
    ResendClose,
}

/// What the driver's own components have to send on one link path at one
/// moment (`DriverContent`): the intents of the content they hold, such as
/// the acknowledgments due and the CRYPTO data unsent, and the facts of the
/// link path's sealed close packet. The sending call gathers it afresh for
/// each datagram and hands it to the planner
/// ([`LinkPathSendPlanner::poll_plan`]); none of it has a ticket, and a
/// frame source that writes some of it changes its own state, so the next
/// gathering no longer has it. Whether content fits is the writing's to
/// find; the least room an intent gives only says when it may.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverContent<J> {
    /// The intents, in the order of the parts and of each part's content.
    pub intents: Vec<J>,
    /// The link path's close packet, once it is sealed.
    pub close: Option<CloseResendFacts>,
}

impl<J> DriverContent<J> {
    /// No content.
    pub const fn new() -> Self {
        Self {
            intents: Vec::new(),
            close: None,
        }
    }

    /// Forget all content, keeping the room of the intents for the next
    /// gathering.
    pub fn clear(&mut self) {
        self.intents.clear();
        self.close = None;
    }
}

impl<J> Default for DriverContent<J> {
    fn default() -> Self {
        Self::new()
    }
}

/// What a link path's sealed close packet gives a planner to decide
/// whether it goes out again (`CloseResendFacts`): how many datagrams the
/// link path received since it was sealed. The close packet stays with the
/// link path, and is sent as it was sealed; whether and when it goes again
/// is the strategy's, which a plan answers with
/// [`PlannedDatagram::ResendClose`]: an endpoint in the closing period
/// should limit the rate at which it sends it (RFC 9000 §10.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CloseResendFacts {
    /// The datagrams received on the link path since the close packet was
    /// sealed.
    pub datagrams_received: u64,
}

/// The content planned first in a packet: the packet's kind, its frame
/// source, the least room it needs and whether it counts in the bytes in
/// flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeadingContent<Id> {
    /// The kind of packet it goes in.
    pub packet: PlannedPacketKind,
    /// The frame source that supplies it.
    pub source: Id,
    /// The least room it needs.
    pub min: MinimumLengths,
    /// Whether it counts in the bytes in flight: the room it takes is
    /// limited as that class's is.
    pub class: FlightClass,
}

/// The plan of one datagram; dropping it ends the datagram.
pub trait DatagramFillPlan<I: SendStrategyTypes> {
    /// What the plan is told after each supply.
    type Feedback: SupplyFeedback;
    /// The cursor of an Initial packet.
    type Initial<'p>: FrameSourceCursor<I::InitialFrameSources, Feedback = Self::Feedback>
    where
        Self: 'p;
    /// The cursor of a Handshake packet.
    type Handshake<'p>: FrameSourceCursor<I::HandshakeFrameSources, Feedback = Self::Feedback>
    where
        Self: 'p;
    /// The cursor of a 0-RTT packet.
    type ZeroRtt<'p>: FrameSourceCursor<I::ZeroRttFrameSources, Feedback = Self::Feedback>
    where
        Self: 'p;
    /// The cursor of a 1-RTT packet.
    type OneRtt<'p>: FrameSourceCursor<I::OneRttFrameSources, Feedback = Self::Feedback>
    where
        Self: 'p;
    /// The cursor of a 1-RTT packet of a candidate link path.
    type OneRttProbe<'p>: FrameSourceCursor<I::ProbeFrameSources, Feedback = Self::Feedback>
    where
        Self: 'p;
    /// The cursor of a 1-RTT packet of a settling link path, a probing
    /// packet.
    type SettlingProbe<'p>: FrameSourceCursor<I::SettlingFrameSources, Feedback = Self::Feedback>
    where
        Self: 'p;

    /// The content planned first in the datagram, before it is opened: the
    /// connection ID is chosen and the datagram's floor follows from it.
    fn leading_content(&self) -> Option<LeadingContent<I::FrameSourceId>>;

    /// The content planned first in the packet after the current one,
    /// without moving on.
    fn peek_next_packet(&self) -> Option<LeadingContent<I::FrameSourceId>>;

    /// The cursor of the next packet; the plan moves on.
    fn next_packet(&mut self) -> Option<PlannedPacket<'_, I, Self>>;
}

/// The cursor of the next packet of a plan, by the packet's kind.
pub enum PlannedPacket<'p, I: SendStrategyTypes, P: DatagramFillPlan<I> + ?Sized + 'p> {
    /// An Initial packet.
    Initial(P::Initial<'p>),
    /// A Handshake packet.
    Handshake(P::Handshake<'p>),
    /// A 0-RTT packet.
    ZeroRtt(P::ZeroRtt<'p>),
    /// A 1-RTT packet.
    OneRtt(P::OneRtt<'p>),
    /// A 1-RTT packet of a candidate link path.
    OneRttProbe(P::OneRttProbe<'p>),
    /// A 1-RTT packet of a settling link path, a probing packet.
    SettlingProbe(P::SettlingProbe<'p>),
}

impl<'p, I: SendStrategyTypes, P: DatagramFillPlan<I> + ?Sized + 'p> PlannedPacket<'p, I, P> {
    /// The kind of the packet.
    pub fn kind(&self) -> PlannedPacketKind {
        match self {
            Self::Initial(_) => PlannedPacketKind::Initial,
            Self::Handshake(_) => PlannedPacketKind::Handshake,
            Self::ZeroRtt(_) => PlannedPacketKind::ZeroRtt,
            Self::OneRtt(_) => PlannedPacketKind::OneRtt,
            Self::OneRttProbe(_) => PlannedPacketKind::OneRttProbe,
            Self::SettlingProbe(_) => PlannedPacketKind::SettlingProbe,
        }
    }
}

impl<'p, I: SendStrategyTypes, P: DatagramFillPlan<I> + ?Sized + 'p> fmt::Debug
    for PlannedPacket<'p, I, P>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PlannedPacket").field(&self.kind()).finish()
    }
}

/// What a plan is told about an item it planned: how many bytes its frame
/// source wrote, frames and frame headers included.
pub trait SupplyFeedback {
    /// The item just supplied wrote `written` bytes.
    fn supplied(&mut self, written: usize);
}

/// The cursor over the planned items of one packet, whose frame sources
/// are the set `S`.
pub trait FrameSourceCursor<S: FrameSourceSet> {
    /// What the plan is told after each supply.
    type Feedback: SupplyFeedback;

    /// The next planned item; until it is supplied or dropped there is no
    /// next one.
    fn next(&mut self) -> Option<PlannedItem<'_, S::Item<'_>, Self::Feedback>>;
}

/// One planned item: one intent of one frame source.
///
/// The item reaches its frame source only through [`supply`](Self::supply),
/// which measures how much was written and hands it back to the plan.
/// Dropped without being supplied, the item was not given to its source,
/// and wrote nothing.
pub struct PlannedItem<'c, T, F: ?Sized> {
    item: T,
    min: MinimumLengths,
    class: FlightClass,
    last_in_packet: bool,
    holds_place: bool,
    feedback: &'c mut F,
}

impl<T: fmt::Debug, F: ?Sized> fmt::Debug for PlannedItem<'_, T, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlannedItem")
            .field("item", &self.item)
            .field("min", &self.min)
            .field("class", &self.class)
            .field("last_in_packet", &self.last_in_packet)
            .field("holds_place", &self.holds_place)
            .finish_non_exhaustive()
    }
}

impl<'c, T, F: SupplyFeedback + ?Sized> PlannedItem<'c, T, F> {
    /// The planned item `item`, needing at least `min` of the room of
    /// `class`, the last item of its packet if `last_in_packet`, ending the
    /// datagram when it writes nothing if `holds_place`; what is written for
    /// it goes back to `feedback`.
    pub fn new(
        item: T,
        min: MinimumLengths,
        class: FlightClass,
        last_in_packet: bool,
        holds_place: bool,
        feedback: &'c mut F,
    ) -> Self {
        Self {
            item,
            min,
            class,
            last_in_packet,
            holds_place,
            feedback,
        }
    }

    pub(crate) fn item(&self) -> &T {
        &self.item
    }

    /// The least room the item needs.
    pub fn min(&self) -> MinimumLengths {
        self.min
    }

    /// Whether the item counts in the bytes in flight: the room it may take
    /// is that class's.
    pub fn class(&self) -> FlightClass {
        self.class
    }

    /// Whether the item is the last one planned for its packet.
    pub fn last_in_packet(&self) -> bool {
        self.last_in_packet
    }

    /// Whether the item holds its place: when it writes nothing, nothing
    /// after it goes into the datagram, and the next datagram starts with
    /// it. An item that does not hold its place and writes nothing is
    /// passed over for the next one.
    pub fn holds_place(&self) -> bool {
        self.holds_place
    }

    /// Give the item to its frame source: `source` writes it into `packet`
    /// and hands back what it holds afterwards. The bytes written, measured
    /// before and after, go back to the plan.
    pub fn supply<W: PacketWriting, P>(
        self,
        packet: OpenPacket<W, ClassOfSource, P>,
        source: impl FnOnce(T, OpenPacket<W, ClassOfSource, P>) -> Supplied<W, ClassOfSource, P>,
    ) -> Supplied<W, ClassOfSource, P> {
        let before = packet.buffer_len();
        let supplied = source(self.item, packet);
        self.feedback
            .supplied(supplied.buffer_len().saturating_sub(before));
        supplied
    }
}

/// The frame sources one kind of packet may carry, as one set: an item is
/// one intent of one of them, borrowed from the strategy.
pub trait FrameSourceSet {
    /// The sum of intents the items are taken from.
    type Intents: 'static;
    /// The frame sources of the set.
    type FrameSourceId;
    /// One item of the set.
    type Item<'a>;

    /// The item for `intent`, if the set's packets can carry it.
    fn item(intent: &Self::Intents) -> Option<Self::Item<'_>>;

    /// The frame source of `item`.
    fn source(item: &Self::Item<'_>) -> Self::FrameSourceId;
}

// ---- how intents end ----

/// Where an intent with a ticket stands; `End` is how it can end other
/// than by being consumed or withdrawn, for the kind of ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentState<End> {
    /// Still waiting to be sent.
    Waiting,
    /// Still waiting to be sent, but none of the active link paths its
    /// destination allows can carry it now, as they are; it waits for one
    /// that can, and may be withdrawn.
    WaitingTooLarge,
    /// Written into a packet.
    Consumed,
    /// Withdrawn by its holder.
    Withdrawn,
    /// Ended.
    Ended(End),
}

/// What withdrawing an intent tells, when consuming and withdrawing it may
/// happen at once on two threads: which of them took place, as only one
/// does. `End` is how the intent can end other than by being consumed or
/// withdrawn, for the kind of ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentWithdrawReport<End> {
    /// The withdrawal took place: the intent was not written into a packet,
    /// and it will not be.
    Withdrawn,
    /// The intent was written into a packet before it could be withdrawn.
    Consumed,
    /// The intent had ended before it could be withdrawn, as the connection
    /// closed or its destination ended.
    Ended(End),
}

/// A ticket that changes the room its intent needs (`IntentTicketResize`).
///
/// What the intent is for, such as its frame source or stream, stays: only
/// the least room changes.
pub trait IntentTicketResize {
    /// The intent needs at least `min` from now on.
    fn resize(&mut self, min: MinimumLengths);
}

/// A ticket that withdraws its intent (`IntentTicketWithdraw`).
pub trait IntentTicketWithdraw {
    /// What withdrawing tells.
    type Report;

    /// Withdraw the intent: it is not written into a packet after this.
    fn withdraw(self) -> Self::Report;
}

/// A ticket that goes without withdrawing its intent
/// (`IntentTicketRelease`): its frame was written, and the plan that gave
/// it consumes it.
pub trait IntentTicketRelease {
    /// Let the ticket go without withdrawing its intent.
    fn release(self);
}

/// A ticket that tells where its intent stands now (`IntentTicketState`).
pub trait IntentTicketState {
    /// How the intent can end other than by being consumed or withdrawn.
    type End;

    /// Where the intent stands now.
    fn state(&self) -> IntentState<Self::End>;
}
