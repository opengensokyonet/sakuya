//! The send strategy: where send intents go, in what order, whether they
//! are admitted, and what one datagram carries.
//!
//! A frame source that has something to send publishes a send intent
//! ([`SendIntent`]) and gets back what the strategy gives for that kind of
//! intent: a ticket to resize or withdraw it, or nothing. On the driver's
//! side the strategy is two kinds of values the driver holds and lends to
//! calls: the core ([`SendStrategy`]), in the connection node, which takes
//! intents whose destination is not fixed ([`PublishTo`]); and the send
//! planner of each link path ([`LinkPathSendPlanner`]), in the link path's
//! node, which takes intents bound to that link path ([`Publish`]) and the
//! changes of its send conditions ([`Observe`]). The sending call of a link
//! path asks its planner for the plan of the next datagram
//! ([`LinkPathSendPlanner::poll_plan`]); the plan ([`DatagramFillPlan`])
//! names the packets to write and, in each, the planned items in order; each
//! item reaches its frame source only through [`PlannedItem::supply`], which
//! hands back to the plan how much was written.
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
use snafu::Snafu;

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
}

/// A change of the conditions a link path sends under: its windows, the
/// pacer's release, the probe permit, the connection IDs it may use, the
/// anti-amplification credit, the packet number length.
pub trait SendConditionChange {}

/// `R: PublishOutcome<J, D>`: what `R` gives back for an intent `J`
/// published for the destination `D`, wherever `J` is in the composition's
/// sum of intents: a ticket for intents someone reads or withdraws, `()`
/// for intents sent and forgotten, in a `Result` when the destination may
/// refuse them. A component that keeps what it gets back names its type by
/// this, without the place of `J`.
pub trait PublishOutcome<J: SendIntent, D> {
    /// What publishing gives back.
    type Outcome;
}

/// The destination of an intent published on a link path's send planner:
/// that link path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PlannerLinkPath;

/// `R: Publish<J, Idx>`: `R` takes intents `J` whose destination is the
/// link path of `R`.
///
/// `Idx` is the place of `J` in the composition's sum of intents; the
/// compiler infers it.
pub trait Publish<J: SendIntent, Idx>: PublishOutcome<J, PlannerLinkPath> {
    /// Publish `intent`.
    fn publish(&mut self, intent: J) -> <Self as PublishOutcome<J, PlannerLinkPath>>::Outcome;
}

/// `R: PublishTo<J, D, Idx>`: `R` takes intents `J` for the destination
/// `D`. The core of a strategy implements it for the intents the driver's
/// components publish.
pub trait PublishTo<J: SendIntent, D, Idx>: PublishOutcome<J, D> {
    /// Publish `intent` for `destination`.
    fn publish_to(&mut self, intent: J, destination: D) -> <Self as PublishOutcome<J, D>>::Outcome;
}

/// `R: Observe<J>`: `R` takes the changes `J` of its send conditions.
///
/// It is given the current value; the same value given again is no
/// change.
pub trait Observe<J: SendConditionChange> {
    /// The conditions are now `change`.
    fn observe(&mut self, change: J);
}

/// The destination of content any active link path may send, including
/// one that becomes active later. A component whose intents go there asks
/// for `S::Destination: From<AnyActiveLinkPath>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AnyActiveLinkPath;

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
        let credit = self.anti_amplification_credit.map_or(usize::MAX, |credit| {
            usize::try_from(credit).unwrap_or(usize::MAX)
        });
        let any = self.max_udp_payload().min(credit);
        match class {
            FlightClass::AckOnly => any,
            FlightClass::InFlight if self.probe_permits > 0 => any,
            FlightClass::InFlight => any
                .min(self.congestion_window_left)
                .min(self.pacing_allowance),
        }
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
            | PlannedPacketKind::SettlingResponse => self.one_rtt,
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
}

/// What one part sends: its intents and its frame sources. Implemented by
/// the marker type of the part.
pub trait SendIntentPart {
    /// The part's frame sources, as one type.
    type FrameSourceId;
    /// The part's intents: a sum of its intent types; `CNil` when it sends
    /// nothing.
    type SendIntents: PartSendIntents<Self::FrameSourceId> + 'static;
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
}

/// Putting an intent `J` into a sum of the parts' intents `Self`: into its
/// part's sum, then at that part's position. `Idx` is the pair of places;
/// the compiler infers it.
pub trait InjectSendIntent<J, Idx> {
    /// The sum holding `intent`.
    fn inject(intent: J) -> Self;
}

/// The place of an intent in the part at the head of a sum, with `Inner`
/// its place in that part's own sum.
#[derive(Debug)]
pub enum InHead<Inner> {
    #[doc(hidden)]
    _Never(PhantomData<Inner>, core::convert::Infallible),
}

/// The place of an intent in a later part of a sum.
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
    /// A 1-RTT packet of a settling link path: PATH_RESPONSE only.
    SettlingResponse,
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
/// intents the driver's components publish whose destination is not fixed
/// ([`PublishTo`]) and the connection's events.
///
/// Dropping the core is the end of all sending.
pub trait SendStrategy<I: SendStrategyTypes>: Sized {
    /// Where an intent may go; what it means is the strategy's. A
    /// component that needs a destination asks for it on its own
    /// `where` clause.
    type Destination;
    /// The send planner of one link path.
    type LinkPathSendPlanner: LinkPathSendPlanner<I, Core = Self>;

    /// A link path `id` begins, in `role`: its send planner.
    fn add_link_path(
        &mut self,
        id: I::LinkPathIdentifier,
        role: LinkPathRoleKind,
    ) -> Self::LinkPathSendPlanner;

    /// The keys to send packets at `level` are now in place.
    fn send_keys_available(&mut self, level: EncryptionLevel);

    /// The handshake is confirmed: no more Initial or Handshake packets
    /// are sent.
    fn handshake_confirmed(&mut self);

    /// No link path will be active again, for `reason`: intents whose
    /// destination is any active link path end.
    fn no_more_active_link_paths(&mut self, reason: CloseReason<I::CloseCause>);
}

/// The send planner of one link path: held in the link path's node; it
/// takes the intents bound to that link path ([`Publish`]) and the changes
/// of its send conditions ([`Observe`]), and plans each datagram.
pub trait LinkPathSendPlanner<I: SendStrategyTypes>: Sized {
    /// The core it plans with.
    type Core;
    /// The plan of one datagram, borrowing the planner and the core.
    type Plan<'a>: DatagramFillPlan<I>
    where
        Self: 'a,
        Self::Core: 'a;

    /// The plan of the next datagram, once there is one; while there is
    /// none, the waker is kept and woken when there may be.
    fn poll_plan<'a>(
        &'a mut self,
        core: &'a mut Self::Core,
        cx: &mut Context<'_>,
    ) -> Poll<PlannedDatagram<Self::Plan<'a>>>;

    /// The link path's role is now `role`.
    fn role_changed(&mut self, core: &mut Self::Core, role: LinkPathRoleKind);

    /// The link path ended.
    fn ended(self, core: &mut Self::Core);
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
    /// The cursor of a 1-RTT packet of a settling link path.
    type SettlingResponse<'p>: FrameSourceCursor<I::SettlingFrameSources, Feedback = Self::Feedback>
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
    /// A 1-RTT packet of a settling link path.
    SettlingResponse(P::SettlingResponse<'p>),
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
            Self::SettlingResponse(_) => PlannedPacketKind::SettlingResponse,
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

/// What a plan is told after an item was supplied: how many bytes its
/// frame source wrote, frames and frame headers included.
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
/// Dropped without being supplied, the item was not given to its source.
pub struct PlannedItem<'c, T, F: ?Sized> {
    item: T,
    min: MinimumLengths,
    class: FlightClass,
    last_in_packet: bool,
    feedback: &'c mut F,
}

impl<T: fmt::Debug, F: ?Sized> fmt::Debug for PlannedItem<'_, T, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlannedItem")
            .field("item", &self.item)
            .field("min", &self.min)
            .field("class", &self.class)
            .field("last_in_packet", &self.last_in_packet)
            .finish_non_exhaustive()
    }
}

impl<'c, T, F: SupplyFeedback + ?Sized> PlannedItem<'c, T, F> {
    /// The planned item `item`, needing at least `min` of the room of
    /// `class`, the last item of its packet if `last_in_packet`; what is
    /// written for it goes back to `feedback`.
    pub fn new(
        item: T,
        min: MinimumLengths,
        class: FlightClass,
        last_in_packet: bool,
        feedback: &'c mut F,
    ) -> Self {
        Self {
            item,
            min,
            class,
            last_in_packet,
            feedback,
        }
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

/// The role a link path is in does not take the intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("the link path in its role {role:?} does not take this intent"))]
pub struct RoleNotAcceptingError {
    role: LinkPathRoleKind,
}

impl RoleNotAcceptingError {
    /// The error for a link path in `role`.
    pub fn new(role: LinkPathRoleKind) -> Self {
        Self { role }
    }

    /// The role of the link path.
    pub fn role(&self) -> LinkPathRoleKind {
        self.role
    }
}

/// The link path has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Snafu)]
#[snafu(display("the link path has ended"))]
pub struct LinkPathEndedError;

/// Why a link path did not take or keep an intent published on its
/// planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
pub enum LinkPathPublishError {
    /// Its role does not take the intent.
    #[snafu(transparent)]
    RoleNotAccepting {
        /// The failure.
        source: RoleNotAcceptingError,
    },
    /// It has ended.
    #[snafu(transparent)]
    LinkPathEnded {
        /// The failure.
        source: LinkPathEndedError,
    },
}

/// An intent a link path's planner refused, handed back.
#[derive(Snafu)]
#[snafu(display("the link path refused the intent"))]
pub struct IntentRejected<J> {
    intent: J,
    source: LinkPathPublishError,
}

impl<J> fmt::Debug for IntentRejected<J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntentRejected")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl<J> IntentRejected<J> {
    /// `intent`, refused for `source`.
    pub fn new(intent: J, source: LinkPathPublishError) -> Self {
        Self { intent, source }
    }

    /// Why it was refused.
    pub fn error(&self) -> &LinkPathPublishError {
        &self.source
    }

    /// The intent back.
    pub fn into_intent(self) -> J {
        self.intent
    }
}

/// Where an intent with a ticket stands; `End` is how it can end other
/// than by being consumed or withdrawn, for the kind of ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentState<End> {
    /// Still waiting to be sent.
    Waiting,
    /// Written into a packet.
    Consumed,
    /// Withdrawn by its holder.
    Withdrawn,
    /// Ended.
    Ended(End),
}
