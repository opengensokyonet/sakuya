//! A send strategy that plans as the ranked strategy does and records what
//! the connection's components tell and publish to it.
use core::{
    cell::RefCell,
    fmt::Debug,
    task::{Context, Poll},
};
use std::thread_local;

use sakuya_connection::send_strategy::{
    AnyActiveLinkPath, DatagramLimits, InjectSendIntent, IntentRejected, LinkPathRoleKind,
    LinkPathSendPlanner, Observe, PacketOverheads, PlannedDatagram, PlannerLinkPath, Publish,
    PublishOutcome, PublishTo, SendIntent, SendStrategy, SendStrategyTypes,
    ranked::{
        IntentTicket, LinkPathIntentTicket, RankedIntent, RankedLinkPathSendPlanner,
        RankedSendStrategy,
    },
};
use sakuya_stream::connection::CloseReason;
use sakuya_wire::v1::encryption_level::EncryptionLevel;

thread_local! {
    static EVENTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
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
        Self {
            inner: RankedSendStrategy::new(),
            link_paths: 0,
        }
    }
}

impl<I: SendStrategyTypes, J: SendIntent> PublishOutcome<J, AnyActiveLinkPath>
    for EventLoggingSendStrategy<I>
{
    type Outcome = RecordedTicket<IntentTicket<I::CloseCause>>;
}

impl<I, J, Idx> PublishTo<J, AnyActiveLinkPath, Idx> for EventLoggingSendStrategy<I>
where
    I: SendStrategyTypes,
    J: SendIntent + Debug,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish_to(
        &mut self,
        intent: J,
        destination: AnyActiveLinkPath,
    ) -> RecordedTicket<IntentTicket<I::CloseCause>> {
        let label = format!("{intent:?}");
        record(format!("core: publish {label}"));
        RecordedTicket {
            owner: "core".to_owned(),
            intent: label,
            inner: <RankedSendStrategy<I> as PublishTo<J, AnyActiveLinkPath, Idx>>::publish_to(
                &mut self.inner,
                intent,
                destination,
            ),
        }
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

impl<I: SendStrategyTypes, J: SendIntent> PublishOutcome<J, PlannerLinkPath>
    for EventLoggingPlanner<I>
{
    type Outcome = Result<RecordedTicket<LinkPathIntentTicket>, IntentRejected<J>>;
}

impl<I, J, Idx> Publish<J, Idx> for EventLoggingPlanner<I>
where
    I: SendStrategyTypes,
    J: SendIntent + Debug,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish(
        &mut self,
        intent: J,
    ) -> Result<RecordedTicket<LinkPathIntentTicket>, IntentRejected<J>> {
        let owner = format!("path {}", self.index);
        let label = format!("{intent:?}");
        let ticket =
            <RankedLinkPathSendPlanner<I> as Publish<J, Idx>>::publish(&mut self.inner, intent)?;
        record(format!("{owner}: publish {label}"));
        Ok(RecordedTicket {
            owner,
            intent: label,
            inner: ticket,
        })
    }
}

impl<I: SendStrategyTypes> Observe<DatagramLimits> for EventLoggingPlanner<I> {
    fn observe(&mut self, change: DatagramLimits) {
        self.inner.observe(change);
    }
}

impl<I: SendStrategyTypes> Observe<PacketOverheads> for EventLoggingPlanner<I> {
    fn observe(&mut self, change: PacketOverheads) {
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
