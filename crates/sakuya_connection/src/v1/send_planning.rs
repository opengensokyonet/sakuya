//! The send strategy in the connection's tree: its core in the connection
//! node, a send planner in the node of each link path, and what each is
//! told when the components it follows change.
//!
//! Whoever changes a key, the handshake's confirmation, the record of why
//! the connection closed or a link path's role only changes its own
//! component and publishes what happened; the core and the planners
//! subscribe to those events and read the components again. Each remembers
//! what it told the strategy last, so the same fact is told once.

use crate::role::LinkPathRoleChanged;
use core::{fmt, task::Waker};
use sakuya_wire_v1::frame::write::FlightClass;
use std::sync::Arc;

use sakuya_link::Link;
use sakuya_packet_protection_v1::{backend::AEAD_TAG_LEN, packet_number::TruncatedPacketNumber};
use sakuya_wire::parts::{CoprodInjector, Selector};
use sakuya_wire_v1::{
    encryption_level::EncryptionLevel,
    packet_number::PacketNumber,
    role::Role,
    transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, integer::MaxUdpPayloadSize,
    },
};
use sakuya_wire_v1::{
    header::SAMPLE_DISTANCE,
    parameters::ParametersOf,
    var_int::{VarInt, VarIntWidth},
};

use sakuya_recovery_v1::{
    congestion::CongestionController,
    pacing::Pacer,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pmtu::PmtuPolicy,
    send_journals::SendJournals,
};

use sakuya_stream_v1::{connection::CloseReason, send_options::destination::Unfulfilled};

use super::{
    Choices, CloseCauseOf, OwnZeroRttKeysOf, Side,
    amplification::AntiAmplification,
    close::{CloseReasonRecord, LocalCloseCause},
    component_events::{
        AckPendingChanged, AckReceived, AmplificationCreditChanged, ClosePacketChanged,
        CloseReasonWritten, CongestionChanged, CryptoOutputChanged,
        DestinationConnectionIdsChanged, HandshakeConfirmed, HandshakeDonePendingChanged,
        KeysDiscarded, KeysInstalled, LinkCeilingChanged, LocalConnectionIdsChanged,
        NewTokenPendingChanged, PacketsSent, PathChallengePendingChanged,
        PathResponsePendingChanged, PeerTransportParametersKnown, PmtuConcluded,
        PmtuProbePendingChanged, ProbePingsChanged, RetryReceived, SendIntentsChanged,
        SpaceRetired, level,
    },
    confirmation::HandshakeConfirmation,
    connection_ids::{ConnectionIdsOf, ResetTokenRegistrarOf},
    error::{ConnectionError, V1ConnectionErrorOf},
    feedback::LineageFeedback,
    keys::{HandshakeKeys, InitialKeys, OneRttKeys},
    link::{LinkClone, LinkFacts},
    parameters::PeerTransportParameters,
    pmtu_probe::PendingPmtuProbe,
    receive::v1_error,
    recovery::{CongestionPartOf, LinkPathCongestionState, PmtuOf, peer_max_udp_payload_size},
    send::SendTypes,
    spaces::SendJournalsOf,
};
use crate::role::LinkPathRole;
use crate::v1::{HostChoices, HostOf};
use crate::{
    call::CallBundle,
    clock::{InstantOf, LinkIdOf},
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, RequestOf,
    },
    component_event::{EventSubscriptions, Happened, NodeEnding, NodeStarted, TriggeredEvents},
    connection_id::DestinationConnectionIdStrategy,
    error::ConnectionErrorsOf,
    feedback::FeedbackSummariesOf,
    frame_source::{
        DriverContentOf, EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts,
    },
    layer::{self, NodeKey},
    others::OtherNodes,
    send_strategy::{
        AnyActiveLinkPath, DatagramLimits, DriverContent, FrameSourceSet, IntentPublisher,
        IntentState, IntentTicketChanges, IntentTicketRelease, IntentTicketResize,
        IntentTicketState, IntentTicketWithdraw, LinkPathRoleKind, LinkPathSendPlanner,
        MinimumLengths, Observe, PacketOverheads, PlacedPublisher, PlanChange, PlannedPacketKind,
        PublishOutcome, PublishTo, SendIntent, SendIntentHandle, SendIntentPublisher,
        SendIntentsOf, SendStrategy, SendStrategyTypes, SharedPublishTo, SharedSendStrategy,
    },
    share::{FlatMut, FlatRef, LineageLists, LineagePartList, LogicalPathKeys, NodeData},
    take::{GetAt, ReadEach, Take, TakeEach},
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

/// The publisher of the send strategy of the choices `T` and the list of
/// parts `L`.
pub type PublisherOf<T, L> = <SendStrategyOf<T, L> as SendStrategy<SendTypes<T, L>>>::Publisher;

/// The publisher of the send strategy that the strategy types `I` of a
/// host run on.
pub type StrategyPublisherOf<I> =
    <<I as HostSendStrategyTypes>::Strategy as SendStrategy<I>>::Publisher;

/// What the publisher of the send strategy that the strategy types `I` run
/// on gives back for an intent `J` for any active link path: the ticket a
/// component keeps for it.
pub type PublishedTicketOf<I, J> =
    <StrategyPublisherOf<I> as PublishOutcome<J, AnyActiveLinkPath>>::Outcome;

/// `R: StrategyPublisherFor<J, Idx>`: `R`, the publisher of a send
/// strategy, takes intents `J` for any active link path at the place `Idx`
/// through `&mut`, and resizes, withdraws and lets go the tickets it gives
/// back for them. A component lent the publisher publishes through it
/// placed ([`PlacedPublisher`]); this bound is what that asks of it.
pub trait StrategyPublisherFor<J: SendIntent, Idx>:
    PublishTo<J, AnyActiveLinkPath, Idx>
    + IntentTicketChanges<<Self as PublishOutcome<J, AnyActiveLinkPath>>::Outcome>
{
}

impl<R, J, Idx> StrategyPublisherFor<J, Idx> for R
where
    J: SendIntent,
    R: PublishTo<J, AnyActiveLinkPath, Idx>
        + IntentTicketChanges<<R as PublishOutcome<J, AnyActiveLinkPath>>::Outcome>,
{
}

/// `R: StrategyPublisherForTicket<J, Idx, K>`: as
/// [`StrategyPublisherFor<J, Idx>`], with the ticket `R` gives back for
/// `J` named `K`. A trait method that is lent the publisher states this
/// one with `K` a parameter of its own, which its callers infer: a bound
/// of a trait method that names the ticket through an associated type of
/// the trait cannot be met by an implementation.
pub trait StrategyPublisherForTicket<J: SendIntent, Idx, K>:
    PublishTo<J, AnyActiveLinkPath, Idx>
    + PublishOutcome<J, AnyActiveLinkPath, Outcome = K>
    + IntentTicketChanges<K>
{
}

impl<R, J, Idx, K> StrategyPublisherForTicket<J, Idx, K> for R
where
    J: SendIntent,
    R: PublishTo<J, AnyActiveLinkPath, Idx>
        + PublishOutcome<J, AnyActiveLinkPath, Outcome = K>
        + IntentTicketChanges<K>,
{
}

/// `F: ComponentPublishing<I, J>`: what a component of the kind `F`, such
/// as a kind of stream set, made over the strategy types `I`, publishes its
/// intents `J` through, and the ticket it keeps for each.
///
/// A component held only through the shared connection publishes through
/// the strategy's publisher it is lent, and keeps that publisher's tickets
/// ([`PublishedTicketOf`]); its kind gives every `I`. A component that can
/// also be held apart from the connection publishes through an intake of
/// its own, which it asks the core for when it is built, and keeps the
/// intake's tickets on both ways ([`IntakeTicketOf`]): its kind gives the
/// strategy types whose strategy gives intakes ([`SharedSendStrategy`]).
pub trait ComponentPublishing<I: HostSendStrategyTypes, J: SendIntent> {
    /// The ticket the component keeps for an intent.
    type Ticket;
    /// What the component publishes through apart from the publisher it is
    /// lent: `()` for one that publishes through that publisher.
    type Intake;
}

/// `F: ComponentIntake<I, J, Idx>`: the component of the kind `F` gets what
/// it publishes through apart from the publisher ([`ComponentPublishing`])
/// from the core when it is built, with `Idx` the place of `J` in the sum
/// of intents, which the compiler infers there.
pub trait ComponentIntake<I: HostSendStrategyTypes, J: SendIntent, Idx>:
    ComponentPublishing<I, J>
{
    /// What the component publishes through apart from the publisher.
    fn intake(strategy: &mut I::Strategy) -> Self::Intake;
}

/// A handle of an intake `K` for intents `J` for the destination `D`,
/// giving back `T` (`PlacedIntakeHandle`): the place of `J` in the sum of
/// intents is fixed in the function it publishes with, chosen where the
/// handle is made, so that its type does not name it. A component made
/// over strategy types it cannot name the place in keeps this.
pub struct PlacedIntakeHandle<K, J, D, T> {
    intake: K,
    publish: fn(&K, J, D) -> T,
}

impl<K, J, D, T> PlacedIntakeHandle<K, J, D, T> {
    /// The handle publishing intents `J` at the place `Idx` through
    /// `intake`.
    pub fn new<Idx>(intake: K) -> Self
    where
        K: SharedPublishTo<J, D, Idx> + PublishOutcome<J, D, Outcome = T>,
        J: SendIntent,
    {
        Self {
            intake,
            publish: <K as SharedPublishTo<J, D, Idx>>::publish_to,
        }
    }

    /// The intake.
    pub fn intake(&self) -> &K {
        &self.intake
    }
}

impl<K: Clone, J, D, T> Clone for PlacedIntakeHandle<K, J, D, T> {
    fn clone(&self) -> Self {
        Self {
            intake: self.intake.clone(),
            publish: self.publish,
        }
    }
}

impl<K, J, D, T> fmt::Debug for PlacedIntakeHandle<K, J, D, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlacedIntakeHandle").finish_non_exhaustive()
    }
}

impl<K: Clone, J: SendIntent, D, T> SendIntentHandle<J, D> for PlacedIntakeHandle<K, J, D, T> {
    type Outcome = T;

    fn publish_to(&self, intent: J, destination: D) -> T {
        (self.publish)(&self.intake, intent, destination)
    }
}

/// A handle of the intake publishes as a component's publisher: its tickets
/// resize, withdraw and tell their state themselves.
impl<K, J, D, T> IntentPublisher<J, D> for PlacedIntakeHandle<K, J, D, T>
where
    J: SendIntent,
    T: IntentTicketResize + IntentTicketWithdraw + IntentTicketRelease + IntentTicketState,
{
    type Ticket = T;

    fn publish_to(&mut self, intent: J, destination: D) -> T {
        (self.publish)(&self.intake, intent, destination)
    }

    fn resize(&mut self, ticket: &mut T, min: MinimumLengths) {
        ticket.resize(min);
    }

    fn withdraw(&mut self, ticket: T) {
        let _ = ticket.withdraw();
    }

    fn release_written(&mut self, ticket: T) {
        ticket.release();
    }

    fn waits_too_large(&self, ticket: &T) -> bool {
        matches!(ticket.state(), IntentState::WaitingTooLarge)
    }
}

/// The intake the core of the strategy types `I` gives a component that
/// asks for one.
pub type IntakeOf<I> = <<I as HostSendStrategyTypes>::Strategy as SharedSendStrategy<I>>::Intake;

/// What the intake the core of the strategy types `I` gives back for an
/// intent `J` for any active link path.
pub type IntakeTicketOf<I, J> = <IntakeOf<I> as PublishOutcome<J, AnyActiveLinkPath>>::Outcome;

/// The publisher of the send strategy (`SendStrategyPublisher`), in the
/// connection node beside the core: what the components publish their
/// intents through `&mut`, also while the core is lent elsewhere, such as
/// the frame sources of the streams while a sending call has the core to
/// fill its packets. Whatever publishes through it hands on afterwards
/// whether that may change the plan of a link path
/// ([`take_changed`](Self::take_changed)).
pub struct SendStrategyPublisher<R>(R);

impl<R> fmt::Debug for SendStrategyPublisher<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendStrategyPublisher")
            .finish_non_exhaustive()
    }
}

impl<R: SendIntentPublisher> SendStrategyPublisher<R> {
    /// The component of `publisher`, as a test lends it alone.
    ///
    /// Only for tests: compiled with the feature `test-util`.
    #[cfg(any(test, feature = "test-util"))]
    pub fn new(publisher: R) -> Self {
        Self(publisher)
    }

    /// The publisher.
    pub fn publisher(&self) -> &R {
        &self.0
    }

    /// The publisher, to publish through.
    pub fn publisher_mut(&mut self) -> &mut R {
        &mut self.0
    }

    /// The publisher with the kind of intent `J` and its place `Idx` fixed,
    /// to publish through.
    pub fn placed<J, Idx>(&mut self) -> PlacedPublisher<'_, R, J, Idx> {
        PlacedPublisher::new(&mut self.0)
    }

    /// Whether what was published, resized or withdrawn since this was last
    /// asked may change the plan of a link path: the event that tells the
    /// planners so, to publish at the connection.
    pub fn take_changed(&mut self) -> Option<Happened<SendIntentsChanged>> {
        self.0.take_plan_change().is_possible().then(Happened::new)
    }
}

/// The core and its publisher are made together: the core as the choices'
/// strategy makes it by default, and the publisher empty.
impl<T: Choices, L> Build<T, L, layer::Connection, ()>
    for frunk_core::HList![
        SendStrategyCore<SendStrategyOf<T, L>>,
        SendStrategyPublisher<PublisherOf<T, L>>
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
        let publisher = SendStrategyPublisher(PublisherOf::<T, L>::default());
        frunk_core::hlist![core, publisher]
    }
}

/// It has no deadline and subscribes to nothing: whatever publishes through
/// it tells the planners.
impl<R> PassiveDataComponent for SendStrategyPublisher<R> {}

// ---- the core ----

/// The connection's events the core has been told.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ToldEvents {
    initial_keys: bool,
    handshake_keys: bool,
    zero_rtt_keys: bool,
    one_rtt_keys: bool,
    confirmed: bool,
    closed: bool,
}

/// The core of a send strategy, in the connection node, with the
/// connection's events it has been told. Once every link path drains, no
/// datagram is sent again, and the core is dropped with all it holds.
pub struct SendStrategyCore<S> {
    strategy: CoreState<S>,
    told: ToldEvents,
}

/// Whether the core is still there.
#[derive(Debug)]
enum CoreState<S> {
    /// It is.
    Live(S),
    /// Every link path drained, and it was dropped.
    Dropped,
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
            strategy: CoreState::Live(strategy),
            told: ToldEvents::default(),
        }
    }

    /// The core, unless every link path drained.
    pub fn strategy(&self) -> Option<&S> {
        match &self.strategy {
            CoreState::Live(strategy) => Some(strategy),
            CoreState::Dropped => None,
        }
    }

    /// Every link path drained, so no datagram is sent again: the core is
    /// told first that no link path will be active again, for `reason`, if
    /// it was not told yet, so that the intents it holds end; then it is
    /// dropped with all it holds.
    pub(super) fn drop_strategy<I>(&mut self, reason: Option<CloseReason<I::CloseCause>>)
    where
        I: SendStrategyTypes,
        S: SendStrategy<I>,
    {
        if let CoreState::Live(strategy) = &mut self.strategy
            && !self.told.closed
            && let Some(reason) = reason
        {
            self.told.closed = true;
            strategy.no_more_active_link_paths(reason);
        }
        self.strategy = CoreState::Dropped;
    }

    /// The core, to plan with, unless every link path drained.
    pub fn strategy_mut(&mut self) -> Option<&mut S> {
        match &mut self.strategy {
            CoreState::Live(strategy) => Some(strategy),
            CoreState::Dropped => None,
        }
    }
}

/// The core is told when the keys to send at a level are first in place,
/// when the handshake is confirmed, and, in the poll the reason is
/// recorded, that no link path will be active again: it subscribes to the
/// keys of each level installed, to the handshake confirmed, to the reason
/// for closing written and to the connection built, which has its Initial
/// keys from the start. What may change a plan wakes the sending call of
/// every link path, through its planner (`Kp`).
///
/// The core is dropped by the planner told last that its link path drains
/// (`SendStrategyCore::drop_strategy`).
impl<T: Choices, L, I, Ii, Ih, Iz, Io, If, Ic, Kp>
    DataComponent<T, L, layer::Connection, (I, Ii, Ih, Iz, Io, If, Ic, Kp)>
    for SendStrategyCore<SendStrategyOf<T, L>>
where
    L: LineagePartList<T> + LogicalPathKeys + crate::error::ConnectionErrorsOf,
    SendTypes<T, L>: SendStrategyTypes<CloseCause = CloseCauseOf<T, L>>,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<Self, I>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OwnZeroRttKeysOf<T>, Iz>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<HandshakeConfirmation, If>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, frunk_core::HList![LinkPathPlannerOf<T, L>], Kp>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<KeysInstalled<level::Initial>>()
            .add::<KeysInstalled<level::Handshake>>()
            .add::<KeysInstalled<level::ZeroRtt>>()
            .add::<KeysInstalled<level::OneRtt>>()
            .add::<HandshakeConfirmed>()
            .add::<CloseReasonWritten>()
            .add::<NodeStarted<layer::Connection>>();
    }

    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        others: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        lineage.get::<Self, I>().strategy()?;
        let told = lineage.get::<Self, I>().told;
        let now = ToldEvents {
            initial_keys: told.initial_keys
                || lineage.get::<InitialKeys<T::Crypto>, Ii>().send().is_some(),
            handshake_keys: told.handshake_keys
                || lineage
                    .get::<HandshakeKeys<T::Crypto>, Ih>()
                    .send()
                    .is_some(),
            zero_rtt_keys: told.zero_rtt_keys
                || <T::Side as Side>::zero_rtt_send_keys(lineage.get::<OwnZeroRttKeysOf<T>, Iz>())
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
        let CoreState::Live(strategy) = &mut core.strategy else {
            return None;
        };
        let mut change = PlanChange::None;
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
            (
                told.zero_rtt_keys,
                now.zero_rtt_keys,
                EncryptionLevel::ZeroRtt,
            ),
            (told.one_rtt_keys, now.one_rtt_keys, EncryptionLevel::OneRtt),
        ] {
            if is && !was {
                change = change.or(strategy.send_keys_available(level));
            }
        }
        if now.confirmed && !told.confirmed {
            change = change.or(strategy.handshake_confirmed());
        }
        if let Some(Some(reason)) = reason {
            strategy.no_more_active_link_paths(reason);
        }
        if change.is_possible() {
            others.each_link_path::<frunk_core::HList![LinkPathPlannerOf<T, L>], Kp>(
                |_, frunk_core::hlist_pat![mut planner]| planner.wake(),
            );
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
    /// the planner had nothing to plan or the plan could not be filled: the
    /// one waker of the call, woken when its own content changes, when what
    /// the planner is told may change its plan, and when the blocked call
    /// waits for what the planner is told.
    waker: Option<Waker>,
}

/// Where the sending call of a link path stands after plans it could not
/// fill: content of a level without keys to send with, or that no
/// connection ID offered fits.
///
/// A planner that plans such content keeps no waker. The call wakes itself
/// once, so that the planner, told what the lend changed, plans again;
/// blocked again while nothing it is told has changed, the call waits,
/// with its waker kept beside, until something does.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum BlockedFilling {
    /// The last filling was not blocked, or the planner was told something
    /// new since.
    #[default]
    No,
    /// The last filling was blocked and the call woke itself.
    WokeItself,
    /// Blocked again: the call waits for what the planner is told to
    /// change.
    Waiting,
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
    /// they are now, as the sending call is about to ask it for a plan:
    /// whether that may change the plan is not asked.
    pub(super) fn observe_conditions(&mut self, limits: DatagramLimits, overheads: PacketOverheads)
    where
        P: Observe<DatagramLimits> + Observe<PacketOverheads>,
    {
        self.limits = Some(limits);
        self.overheads = Some(overheads);
        let _ = self.planner.observe(limits);
        let _ = self.planner.observe(overheads);
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
            self.keep_waker(waker);
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
            BlockedFilling::WokeItself | BlockedFilling::Waiting => {
                self.blocked = BlockedFilling::Waiting;
                self.keep_waker(waker);
                false
            }
        }
    }

    fn keep_waker(&mut self, waker: &Waker) {
        match &mut self.waker {
            Some(kept) => kept.clone_from(waker),
            None => self.waker = Some(waker.clone()),
        }
    }

    /// Wake the sending call, if it waits: what it may send changed.
    pub(super) fn wake(&mut self) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    /// Wake the sending call if `change` may change its plan.
    fn wake_if(&mut self, change: PlanChange) {
        if change.is_possible() {
            self.wake();
        }
    }

    /// The planner was told something new: a sending call waiting after a
    /// blocked filling plans again.
    fn told_anew(&mut self) {
        if core::mem::take(&mut self.blocked) == BlockedFilling::Waiting {
            self.wake();
        }
    }

    /// What the driver's components have to send changed from what the
    /// sending call saw, to `content`, in a way the call may send: it is
    /// woken, and `content` is what it saw.
    fn wake_for(&mut self, content: DriverContent<J>) {
        self.seen = content;
        self.wake();
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
        LinkPathRoleKind::Settling => &[PlannedPacketKind::SettlingProbe],
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
        PlannedPacketKind::SettlingProbe => I::SettlingFrameSources::item(intent).is_some(),
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
/// same frame source, needing the same least room, and both riding along or
/// neither: an ACK frame that rode along and is due now is new content.
fn same_content<I: SendStrategyTypes>(a: &I::SendIntents, b: &I::SendIntents) -> bool
where
    I::FrameSourceId: PartialEq,
{
    I::frame_source(a) == I::frame_source(b)
        && I::min_lengths(a) == I::min_lengths(b)
        && I::only_piggybacks(a) == I::only_piggybacks(b)
}

/// Whether the driver's content `now` wakes a sending call that saw `seen`:
/// the facts of the close packet changed, or one of the intents that does
/// not only ride along, by its frame source and least room, is not among
/// those seen and fits an empty datagram of the link path.
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
            !I::only_piggybacks(intent)
                && !seen
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
        let mut core = parents.get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Ic>();
        let planner = match core.strategy_mut() {
            Some(strategy) => strategy.add_link_path(identifier, role),
            // every link path drained, so no datagram goes again: a core
            // of its own plans for it, and it is never asked to
            None => SendStrategyOf::<T, L>::default().add_link_path(identifier, role),
        };
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
        if let Some(strategy) = parents
            .get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Ic>()
            .strategy_mut()
        {
            self.planner.ended(strategy, &mut ended);
        }
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
/// path can send whenever what limits it changes: the logical link's
/// datagram size ceiling and the anti-amplification credit, the peer's
/// transport parameters, and the congestion control, its fixed state and
/// the datagram size probing policy in the link path's recovery layer; and
/// what each kind of packet takes beyond its frames whenever what it
/// follows from changes: the connection IDs, the packet number states and
/// send journals of the spaces, and the keys of each level. It subscribes
/// to the events of all of these, and to its link path and its recovery
/// layer built and the recovery layer ending; it only reads the components.
///
/// Before it gathers the driver's content, it copies the datagram size probe
/// to send ([`PendingPmtuProbe`]) from the probing policy, whose
/// conclusion changed it subscribes to: the policy's probe on an `Active`
/// link path once the handshake, which it subscribes to as confirmed too,
/// is confirmed, unless a probe of that size awaits its result in the fixed
/// congestion state. It changes the component only when the probe to send
/// changes.
///
/// It also subscribes to what the driver's own components have to send on
/// the link path changed ([`DriverContentOf`]): the ACK frames, the CRYPTO
/// output, a server's HANDSHAKE_DONE and NEW_TOKEN frames, the connection IDs, the probe's
/// PINGs, the response to a PATH_CHALLENGE, the datagram size probe, the
/// link path's PATH_CHALLENGE and the close packet. When that content has an intent the sending call did not
/// see last, by its frame source and least room, that fits an empty
/// datagram as the link path can send now, or the close packet's facts
/// changed, the sending call is woken; content that does not fit wakes it
/// once the link path's conditions change so that it does, and content gone
/// since is forgotten as seen.
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
/// established layer's components; the frame sources borrow the strategy's
/// publisher there themselves, and the planner reads it, at `Ipb`, only
/// after. `Hd` holds the positions each part reads its content by.
impl<
    T: Choices,
    L,
    Ip,
    Ir,
    It,
    Il,
    Io,
    Ipp,
    Jc,
    Js,
    Jm,
    Ic,
    Ier,
    Kr,
    Kp,
    Ik,
    Hf,
    Is,
    Ipb,
    Hd,
    Ipm,
    Ihc,
>
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
            (Ik, Hf, Is, Ipb),
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
    SendTypes<T, L>: SendStrategyTypes<CloseCause = CloseCauseOf<T, L>>,
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
            + GetAt<SendStrategyPublisher<PublisherOf<T, L>>, Ipb>
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
    fn subscribes(out: &mut EventSubscriptions) {
        // the role and what limits the link path
        out.add::<LinkPathRoleChanged>()
            .add::<LinkCeilingChanged>()
            .add::<AmplificationCreditChanged>()
            .add::<PeerTransportParametersKnown>()
            .add::<CongestionChanged>()
            .add::<PmtuConcluded>()
            .add::<NodeStarted<layer::LinkPath>>()
            .add::<NodeStarted<layer::Recovery>>()
            .add::<NodeEnding<layer::Recovery>>();
        // what the packet overheads follow from
        out.add::<DestinationConnectionIdsChanged>()
            .add::<AckReceived>()
            .add::<PacketsSent>()
            .add::<SpaceRetired>()
            .add::<RetryReceived>()
            .add::<KeysInstalled<level::Initial>>()
            .add::<KeysInstalled<level::Handshake>>()
            .add::<KeysInstalled<level::ZeroRtt>>()
            .add::<KeysInstalled<level::OneRtt>>()
            .add::<KeysDiscarded<level::Initial>>()
            .add::<KeysDiscarded<level::Handshake>>()
            .add::<KeysDiscarded<level::ZeroRtt>>()
            .add::<KeysDiscarded<level::OneRtt>>();
        // what the driver's content is read from
        out.add::<AckPendingChanged>()
            .add::<CryptoOutputChanged>()
            .add::<HandshakeDonePendingChanged>()
            .add::<LocalConnectionIdsChanged>()
            .add::<ProbePingsChanged>()
            .add::<PathResponsePendingChanged>()
            .add::<PathChallengePendingChanged>()
            .add::<NewTokenPendingChanged>()
            .add::<ClosePacketChanged>()
            .add::<PmtuProbePendingChanged>();
        // what the datagram size probe to send is copied from
        out.add::<HandshakeConfirmed>();
        // what the publisher took may change the plan
        out.add::<SendIntentsChanged>();
    }

    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let role = lineage.get::<LinkPathRole<InstantOf<T>>, Ir>().kind();
        let limits = read_datagram_limits::<T, L, B, Il, Ipp, Jc, Js, Jm>(&lineage, others, role);
        if role == LinkPathRoleKind::Active
            && !limits.supports_minimum()
            && !lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .is_written()
            && !another_can_send::<T, L, B, Kr, Kp>(others)
        {
            let error = v1_error::<L, Ier>(ConnectionError::NoViablePath);
            let written = lineage
                .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .record(CloseReason::Local(Arc::new(LocalCloseCause::Connection(
                    error,
                ))));
            if let Some(written) = written {
                lineage.publish(written);
            }
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
            let changed = lineage.get_mut::<PendingPmtuProbe, Ipm>().set(wanted);
            lineage.publish(changed);
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
        let reason = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .reason()
            .cloned();
        // the publisher stays in the rest: the frame sources that take back
        // what the planner ends borrow it there
        let (frunk_core::hlist_pat![mut planner], mut rest) =
            Take::<frunk_core::HList![Self], It>::take(lineage);
        let told_anew = planner.role != role
            || planner.limits != Some(limits)
            || planner.overheads != Some(overheads);
        if planner.role != role {
            planner.role = role;
            let mut ended = Vec::new();
            if let Some(strategy) = rest
                .get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Ik>()
                .strategy_mut()
            {
                let change = planner.planner.role_changed(strategy, role, &mut ended);
                planner.wake_if(change);
            }
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
        // the planner told last that its link path drains, after every
        // other one was, drops the core: no datagram goes again
        if told_anew
            && role == LinkPathRoleKind::Draining
            && all_others_drained::<T, L, B, Kp>(others)
        {
            rest.get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Ik>()
                .drop_strategy::<SendTypes<T, L>>(reason);
            *rest
                .get_mut::<SendStrategyPublisher<PublisherOf<T, L>>, Ipb>()
                .publisher_mut() = PublisherOf::<T, L>::default();
        }
        if planner.limits != Some(limits) {
            planner.limits = Some(limits);
            let change = planner.planner.observe(limits);
            planner.wake_if(change);
        }
        if planner.overheads != Some(overheads) {
            planner.overheads = Some(overheads);
            let change = planner.planner.observe(overheads);
            planner.wake_if(change);
        }
        // the room the planner leaves with the publisher follows what it
        // was told, and what the publisher took may have reached it
        let mut publisher = rest.get_mut::<SendStrategyPublisher<PublisherOf<T, L>>, Ipb>();
        let change = planner.planner.intents_changed(publisher.publisher_mut());
        planner.wake_if(change);
        if told_anew {
            planner.told_anew();
        }
        None
    }
}

/// Whether every link path other than the lent one was told it drains, as
/// its planner was last told.
fn all_others_drained<'v, T, L, B, Kp>(others: &mut OtherNodes<'v, T, L, B>) -> bool
where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathPlannerOf<T, L>, Kp>,
{
    let mut drained = true;
    others.each_link_path_read::<LinkPathPlannerOf<T, L>, Kp>(|_, planner| {
        drained &= planner.role == LinkPathRoleKind::Draining;
    });
    drained
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

impl CongestionAllowance {
    /// What a candidate without a recovery layer is allowed: its probes
    /// count in no congestion control (RFC 9000 §9.4), the
    /// anti-amplification limit holds what it sends, and path validation
    /// times its challenges.
    pub(super) const UNCONTROLLED: Self = Self {
        window_left: usize::MAX,
        pacing_allowance: usize::MAX,
        pacing_release_pending: false,
        probe_permits: 0,
    };
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
/// least size every path supports (RFC 9000 §14); a candidate's caller
/// gives it [`CongestionAllowance::UNCONTROLLED`] instead.
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

/// What a link path in `role` can send in its next new datagram, read from
/// the link path's lend without taking anything: the pacer is not
/// refilled, so its allowance is what its last refill left. A candidate
/// without a recovery layer sends datagrams of 1200 bytes, held by the
/// anti-amplification limit alone ([`CongestionAllowance::UNCONTROLLED`]).
fn read_datagram_limits<'v, T, L, B, Il, Ipp, Jc, Js, Jm>(
    lineage: &LineageOf<'v, T, L, layer::LinkPath>,
    others: &OtherNodes<'v, T, L, B>,
    role: LinkPathRoleKind,
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
    let recovery = recovery.or_else(|| {
        (role == LinkPathRoleKind::Candidate)
            .then_some((DatagramLimits::MINIMUM, CongestionAllowance::UNCONTROLLED))
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
    OwnZeroRttKeysOf<T>,
    OneRttKeys<<T as crate::v1::MakerChoices>::Crypto, InstantOf<T>>,
    <<T as crate::v1::MakerChoices>::Side as Side>::Own,
];

/// Which levels have keys to send packets with now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SendKeyLevels {
    pub(super) initial: bool,
    pub(super) handshake: bool,
    pub(super) zero_rtt: bool,
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
        next(PacketNumberSpaceKind::ApplicationData, keys.zero_rtt),
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
    let frunk_core::hlist_pat![
        ids, numbers, journals, initial, handshake, zero_rtt, one_rtt, own
    ] = lineage.read_each::<PacketOverheadsReads<T, L>, Io>();
    let keys = SendKeyLevels {
        initial: initial.send().is_some(),
        handshake: handshake.send().is_some(),
        zero_rtt: <T::Side as Side>::zero_rtt_send_keys(zero_rtt).is_some(),
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
/// Length field wide enough for it. `initial`, `handshake`, `zero_rtt` and
/// `one_rtt` are the next packet numbers of the spaces whose levels have
/// keys to send with, `None` for one that has none; 0-RTT and 1-RTT
/// packets share the Application Data space.
#[allow(clippy::too_many_arguments)] // each is a separate fact of the packets
pub(super) fn packet_overheads(
    dcid_len: Option<usize>,
    scid_len: usize,
    initial_token_len: usize,
    max_len: usize,
    initial: Option<NextPacketNumber>,
    handshake: Option<NextPacketNumber>,
    zero_rtt: Option<NextPacketNumber>,
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
        zero_rtt: long(dcid_len, zero_rtt, 0),
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
        // a 0-RTT packet's long header has no token
        assert_eq!(overheads.zero_rtt, overheads.handshake);
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
        let short = packet_overheads(
            Some(0),
            0,
            0,
            1200,
            None,
            None,
            None,
            next(0, None),
            Role::Server,
        );
        assert_eq!(short.one_rtt, Some(1 + 1 + 3 + 16));
        let long = packet_overheads(
            Some(0),
            0,
            0,
            1200,
            None,
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
            None,
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
