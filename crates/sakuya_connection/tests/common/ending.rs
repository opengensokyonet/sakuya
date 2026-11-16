//! A send strategy that plans as the ranked strategy does, keeps the
//! intents published through its intake that a test marks, and ends them,
//! handing them back to the driver, the next time a link path's role
//! changes: as a strategy that ends intents of its own accord.
use core::{
    cell::RefCell,
    fmt::Debug,
    task::{Context, Poll},
};
use std::{
    sync::{Arc, Mutex, PoisonError},
    thread_local,
};

use sakuya_connection::send_strategy::{
    AnyActiveLinkPath, DatagramLimits, InjectSendIntent, IntakeSendIntentHandle,
    IntentRejectedError, LinkPathRoleKind, LinkPathSendPlanner, Observe, PacketOverheads,
    PlannedDatagram, PlannerLinkPath, Publish, PublishOutcome, PublishTo, ResendCloseIntent,
    SendIntent, SendIntentIntake, SendStrategy, SendStrategyTypes, SharedPublishTo,
    ranked::{
        LinkPathIntentTicket, RankedCoreIntent, RankedIntent, RankedLinkPathSendPlanner,
        RankedSendIntake, RankedSendStrategy,
    },
};
use sakuya_connection::v1::send::ProbePingIntent;
use sakuya_stream::connection::CloseReason;
use sakuya_wire::v1::encryption_level::EncryptionLevel;

thread_local! {
    /// What starts the labels of the intents to keep and end.
    static MARKED: RefCell<Option<&'static str>> = const { RefCell::new(None) };
    /// The labels of every intent published through an intake.
    static PUBLISHED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// From now on keep each intent published through the intake whose label,
/// its `Debug` form, starts with `prefix`, and end those kept when a link
/// path's role next changes.
pub fn end_at_next_role_change(prefix: &'static str) {
    MARKED.with(|marked| *marked.borrow_mut() = Some(prefix));
    PUBLISHED.with(|published| published.borrow_mut().clear());
}

/// How many intents whose label starts with `prefix` were published
/// through an intake since [`end_at_next_role_change`].
pub fn published(prefix: &str) -> usize {
    PUBLISHED.with(|published| {
        published
            .borrow()
            .iter()
            .filter(|label| label.starts_with(prefix))
            .count()
    })
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The intents kept, shared by the core, its intake and its planners.
type Kept<J> = Arc<Mutex<Vec<J>>>;

/// The ranked strategy's core, keeping what is marked.
pub struct IntentEndingSendStrategy<I: SendStrategyTypes> {
    inner: RankedSendStrategy<I>,
    kept: Kept<I::SendIntents>,
}

impl<I: SendStrategyTypes> Default for IntentEndingSendStrategy<I> {
    fn default() -> Self {
        Self {
            inner: RankedSendStrategy::new(),
            kept: Arc::default(),
        }
    }
}

impl<I: SendStrategyTypes, J: RankedCoreIntent> PublishOutcome<J, AnyActiveLinkPath>
    for IntentEndingSendStrategy<I>
{
    type Outcome = J::Outcome<I::CloseCause>;
}

impl<I, J, Idx> PublishTo<J, AnyActiveLinkPath, Idx> for IntentEndingSendStrategy<I>
where
    I: SendStrategyTypes,
    J: RankedCoreIntent,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish_to(&mut self, intent: J, destination: AnyActiveLinkPath) -> Self::Outcome {
        <RankedSendStrategy<I> as PublishTo<J, AnyActiveLinkPath, Idx>>::publish_to(
            &mut self.inner,
            intent,
            destination,
        )
    }
}

/// The ranked strategy's intake, keeping what is marked.
pub struct KeepingSendIntake<I: SendStrategyTypes> {
    inner: RankedSendIntake<I>,
    kept: Kept<I::SendIntents>,
}

impl<I: SendStrategyTypes> Clone for KeepingSendIntake<I> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            kept: Arc::clone(&self.kept),
        }
    }
}

impl<I: SendStrategyTypes, J: RankedCoreIntent> PublishOutcome<J, AnyActiveLinkPath>
    for KeepingSendIntake<I>
{
    type Outcome = J::Outcome<I::CloseCause>;
}

impl<I, J, Idx> SharedPublishTo<J, AnyActiveLinkPath, Idx> for KeepingSendIntake<I>
where
    I: SendStrategyTypes,
    J: RankedCoreIntent + Clone + Debug,
    I::SendIntents: InjectSendIntent<J, Idx>,
{
    fn publish_to(&self, intent: J, destination: AnyActiveLinkPath) -> Self::Outcome {
        let label = format!("{intent:?}");
        let marked = MARKED.with(|marked| marked.borrow().is_some_and(|m| label.starts_with(m)));
        if marked {
            lock(&self.kept).push(<I::SendIntents as InjectSendIntent<J, Idx>>::inject(
                intent.clone(),
            ));
        }
        PUBLISHED.with(|published| published.borrow_mut().push(label));
        <RankedSendIntake<I> as SharedPublishTo<J, AnyActiveLinkPath, Idx>>::publish_to(
            &self.inner,
            intent,
            destination,
        )
    }
}

impl<I: SendStrategyTypes> SendIntentIntake<AnyActiveLinkPath> for KeepingSendIntake<I> {
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

impl<I> SendStrategy<I> for IntentEndingSendStrategy<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
    I::LinkPathIdentifier: Clone + PartialEq,
{
    type Destination = AnyActiveLinkPath;
    type LinkPathSendPlanner = IntentEndingPlanner<I>;
    type Intake = KeepingSendIntake<I>;

    fn intake(&self) -> KeepingSendIntake<I> {
        KeepingSendIntake {
            inner: self.inner.intake(),
            kept: Arc::clone(&self.kept),
        }
    }

    fn add_link_path(
        &mut self,
        id: I::LinkPathIdentifier,
        role: LinkPathRoleKind,
    ) -> IntentEndingPlanner<I> {
        IntentEndingPlanner {
            inner: self.inner.add_link_path(id, role),
            kept: Arc::clone(&self.kept),
        }
    }

    fn send_keys_available(&mut self, level: EncryptionLevel) {
        self.inner.send_keys_available(level);
    }

    fn handshake_confirmed(&mut self) {
        self.inner.handshake_confirmed();
    }

    fn no_more_active_link_paths(&mut self, reason: CloseReason<I::CloseCause>) {
        self.inner.no_more_active_link_paths(reason);
    }
}

/// The ranked strategy's planner of one link path, ending what is kept
/// when its role changes.
pub struct IntentEndingPlanner<I: SendStrategyTypes> {
    inner: RankedLinkPathSendPlanner<I>,
    kept: Kept<I::SendIntents>,
}

impl<I: SendStrategyTypes> PublishOutcome<ProbePingIntent, PlannerLinkPath>
    for IntentEndingPlanner<I>
{
    type Outcome = Result<LinkPathIntentTicket, IntentRejectedError<ProbePingIntent>>;
}

impl<I, Idx> Publish<ProbePingIntent, Idx> for IntentEndingPlanner<I>
where
    I: SendStrategyTypes,
    I::SendIntents: InjectSendIntent<ProbePingIntent, Idx>,
{
    fn publish(&mut self, intent: ProbePingIntent) -> Self::Outcome {
        <RankedLinkPathSendPlanner<I> as Publish<ProbePingIntent, Idx>>::publish(
            &mut self.inner,
            intent,
        )
    }
}

impl<I: SendStrategyTypes> PublishOutcome<ResendCloseIntent, PlannerLinkPath>
    for IntentEndingPlanner<I>
{
    type Outcome = ();
}

impl<I: SendStrategyTypes> Publish<ResendCloseIntent, ()> for IntentEndingPlanner<I> {
    fn publish(&mut self, intent: ResendCloseIntent) {
        <RankedLinkPathSendPlanner<I> as Publish<ResendCloseIntent, ()>>::publish(
            &mut self.inner,
            intent,
        );
    }
}

impl<I: SendStrategyTypes> Observe<DatagramLimits> for IntentEndingPlanner<I> {
    fn observe(&mut self, change: DatagramLimits) {
        self.inner.observe(change);
    }
}

impl<I: SendStrategyTypes> Observe<PacketOverheads> for IntentEndingPlanner<I> {
    fn observe(&mut self, change: PacketOverheads) {
        self.inner.observe(change);
    }
}

impl<I> LinkPathSendPlanner<I> for IntentEndingPlanner<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent,
    I::LinkPathIdentifier: Clone + PartialEq,
{
    type Core = IntentEndingSendStrategy<I>;
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

    /// What the ranked planner ends, and every intent kept.
    fn role_changed(
        &mut self,
        core: &mut Self::Core,
        role: LinkPathRoleKind,
        ended: &mut impl Extend<I::SendIntents>,
    ) {
        self.inner.role_changed(&mut core.inner, role, ended);
        ended.extend(lock(&self.kept).drain(..));
        MARKED.with(|marked| marked.borrow_mut().take());
    }

    fn ended(self, core: &mut Self::Core, ended: &mut impl Extend<I::SendIntents>) {
        self.inner.ended(&mut core.inner, ended);
    }
}
