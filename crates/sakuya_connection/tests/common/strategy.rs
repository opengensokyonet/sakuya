//! A send strategy that plans as the ranked strategy does and records what
//! the connection's components tell and publish to it.
use core::{
    cell::{Cell, RefCell},
    fmt::Debug,
    task::{Context, Poll},
};
use std::thread_local;

use sakuya_connection::send_strategy::{
    AnyActiveLinkPath, DatagramLimits, InjectSendIntent, IntentRejectedError, LinkPathRoleKind,
    LinkPathSendPlanner, Observe, PacketOverheads, PlannedDatagram, PlannerLinkPath, Publish,
    PublishOutcome, PublishTo, ResendCloseIntent, SendStrategy, SendStrategyTypes,
    ranked::{
        IntentTicket, LinkPathIntentTicket, RankedCoreIntent, RankedIntent,
        RankedLinkPathSendPlanner, RankedSendStrategy,
    },
};
use sakuya_connection::v1::send::ProbePingIntent;
use sakuya_stream::connection::CloseReason;
use sakuya_wire::v1::encryption_level::EncryptionLevel;

thread_local! {
    static EVENTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static LIMITS: RefCell<Vec<Option<DatagramLimits>>> = const { RefCell::new(Vec::new()) };
    static OVERHEADS: RefCell<Vec<Option<PacketOverheads>>> = const { RefCell::new(Vec::new()) };
    static STALE_INITIAL: Cell<Option<usize>> = const { Cell::new(None) };
    static STALE_INITIAL_KEPT: Cell<Option<usize>> = const { Cell::new(None) };
    static PLAN_NOTHING: Cell<bool> = const { Cell::new(false) };
}

/// Let every planner plan nothing from now on, whatever is published: as a
/// strategy that has nothing it wants to send, so that nothing is sent.
pub fn plan_nothing() {
    PLAN_NOTHING.with(|nothing| nothing.set(true));
}

/// Let the planners plan as the ranked strategy does again, undoing
/// [`plan_nothing`].
pub fn plan_normally() {
    PLAN_NOTHING.with(|nothing| nothing.set(false));
}

/// Let the next packet overheads a planner observes reach the ranked
/// planner with an Initial packet taking `overhead` bytes, whatever they
/// say: as a strategy that plans with what it was told before plans.
pub fn tell_stale_initial_overhead(overhead: usize) {
    STALE_INITIAL.with(|stale| stale.set(Some(overhead)));
}

/// Let every packet overheads a planner observes from now on reach the
/// ranked planner with an Initial packet taking `overhead` bytes: as a
/// strategy that keeps planning Initial packets whether or not there are
/// keys to send them with.
pub fn keep_telling_stale_initial_overhead(overhead: usize) {
    STALE_INITIAL_KEPT.with(|stale| stale.set(Some(overhead)));
}

/// Forget an overhead [`tell_stale_initial_overhead`] left untold, and
/// stop what [`keep_telling_stale_initial_overhead`] started.
pub fn forget_stale_overheads() {
    STALE_INITIAL.with(Cell::take);
    STALE_INITIAL_KEPT.with(Cell::take);
}

fn record(event: impl Into<String>) {
    EVENTS.with(|events| events.borrow_mut().push(event.into()));
}

/// The events the strategy recorded since the last call, in order:
///
/// - `core: keys Initial`, `core: confirmed` and `core: closed <reason>`
///   for what the core was told;
/// - `core: publish <intent>` and `core: drop <intent>` for an intent
///   published for any active link path and for its ticket going;
/// - `path N: added <role>`, `path N: role <role>` and `path N: ended` for
///   the planner of the Nth link path built;
/// - `path N: publish <intent>` and `path N: drop <intent>` for an intent
///   published on that planner and for its ticket going.
pub fn take_strategy_events() -> Vec<String> {
    EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

/// What the planner of the Nth link path built was last told the link path
/// can send; `None` when it was told nothing yet. Each strategy made starts
/// with none told.
pub fn observed_limits(path: usize) -> Option<DatagramLimits> {
    LIMITS.with(|limits| limits.borrow().get(path).copied().flatten())
}

/// What the planner of the Nth link path built was last told each kind of
/// packet takes beyond its frames; `None` when it was told nothing yet.
/// Each strategy made starts with none told.
pub fn observed_overheads(path: usize) -> Option<PacketOverheads> {
    OVERHEADS.with(|overheads| overheads.borrow().get(path).copied().flatten())
}

/// A ticket that records when it goes.
pub struct RecordedTicket<K> {
    owner: String,
    intent: String,
    inner: K,
}

impl<K> RecordedTicket<K> {
    pub fn inner(&self) -> &K {
        &self.inner
    }
}

impl<K> Drop for RecordedTicket<K> {
    fn drop(&mut self) {
        record(format!("{}: drop {}", self.owner, self.intent));
    }
}

/// The ranked strategy's core, recording.
pub struct EventLoggingSendStrategy<I: SendStrategyTypes> {
    inner: RankedSendStrategy<I>,
    link_paths: usize,
}

impl<I: SendStrategyTypes> Default for EventLoggingSendStrategy<I> {
    fn default() -> Self {
        LIMITS.with(|limits| limits.borrow_mut().clear());
        OVERHEADS.with(|overheads| overheads.borrow_mut().clear());
        Self {
            inner: RankedSendStrategy::new(),
            link_paths: 0,
        }
    }
}

/// What the ranked core gives back, as the recording core gives it back: a
/// ticket that records when it goes, or nothing for an intent sent and
/// forgotten.
pub trait RecordOutcome {
    /// What the recording core gives back.
    type Recorded;
    /// The outcome of publishing `intent`, recorded.
    fn recorded(self, intent: String) -> Self::Recorded;
}

impl<C> RecordOutcome for IntentTicket<C> {
    type Recorded = RecordedTicket<IntentTicket<C>>;
    fn recorded(self, intent: String) -> Self::Recorded {
        RecordedTicket {
            owner: "core".to_owned(),
            intent,
            inner: self,
        }
    }
}

impl RecordOutcome for () {
    type Recorded = ();
    fn recorded(self, _: String) {}
}

impl<I: SendStrategyTypes, J: RankedCoreIntent> PublishOutcome<J, AnyActiveLinkPath>
    for EventLoggingSendStrategy<I>
where
    J::Outcome<I::CloseCause>: RecordOutcome,
{
    type Outcome = <J::Outcome<I::CloseCause> as RecordOutcome>::Recorded;
}

impl<I, J, Idx> PublishTo<J, AnyActiveLinkPath, Idx> for EventLoggingSendStrategy<I>
where
    I: SendStrategyTypes,
    J: RankedCoreIntent + Debug,
    J::Outcome<I::CloseCause>: RecordOutcome,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish_to(
        &mut self,
        intent: J,
        destination: AnyActiveLinkPath,
    ) -> <J::Outcome<I::CloseCause> as RecordOutcome>::Recorded {
        let label = format!("{intent:?}");
        record(format!("core: publish {label}"));
        <RankedSendStrategy<I> as PublishTo<J, AnyActiveLinkPath, Idx>>::publish_to(
            &mut self.inner,
            intent,
            destination,
        )
        .recorded(label)
    }
}

impl<I> SendStrategy<I> for EventLoggingSendStrategy<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
    I::LinkPathIdentifier: Clone + PartialEq,
    I::CloseCause: Debug,
{
    type Destination = AnyActiveLinkPath;
    type LinkPathSendPlanner = EventLoggingPlanner<I>;

    fn add_link_path(
        &mut self,
        id: I::LinkPathIdentifier,
        role: LinkPathRoleKind,
    ) -> EventLoggingPlanner<I> {
        let index = self.link_paths;
        self.link_paths += 1;
        record(format!("path {index}: added {role:?}"));
        EventLoggingPlanner {
            inner: self.inner.add_link_path(id, role),
            index,
        }
    }

    fn send_keys_available(&mut self, level: EncryptionLevel) {
        record(format!("core: keys {level:?}"));
        self.inner.send_keys_available(level);
    }

    fn handshake_confirmed(&mut self) {
        record("core: confirmed");
        self.inner.handshake_confirmed();
    }

    fn no_more_active_link_paths(&mut self, reason: CloseReason<I::CloseCause>) {
        record(format!("core: closed {reason:?}"));
        self.inner.no_more_active_link_paths(reason);
    }
}

/// The ranked strategy's planner of one link path, recording.
pub struct EventLoggingPlanner<I: SendStrategyTypes> {
    inner: RankedLinkPathSendPlanner<I>,
    index: usize,
}

impl<I: SendStrategyTypes> PublishOutcome<ProbePingIntent, PlannerLinkPath>
    for EventLoggingPlanner<I>
{
    type Outcome =
        Result<RecordedTicket<LinkPathIntentTicket>, IntentRejectedError<ProbePingIntent>>;
}

impl<I, Idx> Publish<ProbePingIntent, Idx> for EventLoggingPlanner<I>
where
    I: SendStrategyTypes,
    I::SendIntents: InjectSendIntent<ProbePingIntent, Idx>,
{
    fn publish(
        &mut self,
        intent: ProbePingIntent,
    ) -> Result<RecordedTicket<LinkPathIntentTicket>, IntentRejectedError<ProbePingIntent>> {
        let owner = format!("path {}", self.index);
        let label = format!("{intent:?}");
        let ticket = <RankedLinkPathSendPlanner<I> as Publish<ProbePingIntent, Idx>>::publish(
            &mut self.inner,
            intent,
        )?;
        record(format!("{owner}: publish {label}"));
        Ok(RecordedTicket {
            owner,
            intent: label,
            inner: ticket,
        })
    }
}

impl<I: SendStrategyTypes> PublishOutcome<ResendCloseIntent, PlannerLinkPath>
    for EventLoggingPlanner<I>
{
    type Outcome = ();
}

impl<I: SendStrategyTypes> Publish<ResendCloseIntent, ()> for EventLoggingPlanner<I> {
    fn publish(&mut self, intent: ResendCloseIntent) {
        record(format!("path {}: publish {intent:?}", self.index));
        <RankedLinkPathSendPlanner<I> as Publish<ResendCloseIntent, ()>>::publish(
            &mut self.inner,
            intent,
        );
    }
}

impl<I: SendStrategyTypes> Observe<DatagramLimits> for EventLoggingPlanner<I> {
    fn observe(&mut self, change: DatagramLimits) {
        LIMITS.with(|limits| {
            let mut limits = limits.borrow_mut();
            if limits.len() <= self.index {
                limits.resize(self.index + 1, None);
            }
            limits[self.index] = Some(change);
        });
        self.inner.observe(change);
    }
}

impl<I: SendStrategyTypes> Observe<PacketOverheads> for EventLoggingPlanner<I> {
    fn observe(&mut self, mut change: PacketOverheads) {
        OVERHEADS.with(|overheads| {
            let mut overheads = overheads.borrow_mut();
            if overheads.len() <= self.index {
                overheads.resize(self.index + 1, None);
            }
            overheads[self.index] = Some(change);
        });
        if let Some(initial) = STALE_INITIAL
            .with(Cell::take)
            .or(STALE_INITIAL_KEPT.with(Cell::get))
        {
            change.initial = Some(initial);
        }
        self.inner.observe(change);
    }
}

impl<I> LinkPathSendPlanner<I> for EventLoggingPlanner<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
    I::LinkPathIdentifier: Clone + PartialEq,
    I::CloseCause: Debug,
{
    type Core = EventLoggingSendStrategy<I>;
    type Plan<'a>
        = <RankedLinkPathSendPlanner<I> as LinkPathSendPlanner<I>>::Plan<'a>
    where
        Self: 'a;

    fn poll_plan<'a>(
        &'a mut self,
        core: &'a mut Self::Core,
        cx: &mut Context<'_>,
    ) -> Poll<PlannedDatagram<Self::Plan<'a>>> {
        if PLAN_NOTHING.with(Cell::get) {
            return Poll::Pending;
        }
        self.inner.poll_plan(&mut core.inner, cx)
    }

    fn role_changed(&mut self, core: &mut Self::Core, role: LinkPathRoleKind) {
        record(format!("path {}: role {role:?}", self.index));
        self.inner.role_changed(&mut core.inner, role);
    }

    fn ended(self, core: &mut Self::Core) {
        record(format!("path {}: ended", self.index));
        self.inner.ended(&mut core.inner);
    }
}
