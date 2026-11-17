//! A send strategy that plans as the ranked strategy does and records what
//! the connection's components tell it and what the driver's content holds
//! when it is asked for a plan.
use core::{
    cell::{Cell, RefCell},
    fmt::Debug,
    task::{Context, Poll},
};
use std::thread_local;

use sakuya_connection::send_strategy::{
    AnyActiveLinkPath, DatagramLimits, DriverContent, LinkPathRoleKind, LinkPathSendPlanner,
    Observe, PacketOverheads, PlannedDatagram, SendStrategy, SendStrategyTypes,
    ranked::{RankedIntent, RankedLinkPathSendPlanner, RankedSendIntake, RankedSendStrategy},
};
use sakuya_stream::connection::CloseReason;
use sakuya_wire::v1::encryption_level::EncryptionLevel;

thread_local! {
    static EVENTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static LIMITS: RefCell<Vec<Option<DatagramLimits>>> = const { RefCell::new(Vec::new()) };
    static OVERHEADS: RefCell<Vec<Option<PacketOverheads>>> = const { RefCell::new(Vec::new()) };
    static ASKED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
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
/// - `path N: added <role>`, `path N: role <role>` and `path N: ended` for
///   the planner of the Nth link path built;
/// - `path N: content <intent>` and `path N: gone <intent>` for an intent
///   of the driver's content that the planner of the Nth link path is
///   given and was not when it was last asked for a plan, and for one it
///   was given then and no longer is, and `path N: close <count>` when the
///   facts of its sealed close packet are new: the datagrams received since
///   it was sealed.
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

/// How many times the planner of the Nth link path built was asked for a
/// plan since the last call: each time its sending call filled. Each
/// strategy made starts with none asked.
pub fn take_plans_asked(path: usize) -> usize {
    ASKED.with(|asked| {
        asked
            .borrow_mut()
            .get_mut(path)
            .map(std::mem::take)
            .unwrap_or(0)
    })
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
        ASKED.with(|asked| asked.borrow_mut().clear());
        Self {
            inner: RankedSendStrategy::new(),
            link_paths: 0,
        }
    }
}

impl<I> SendStrategy<I> for EventLoggingSendStrategy<I>
where
    I: SendStrategyTypes,
    I::SendIntents: RankedIntent + Debug,
    I::LinkPathIdentifier: Clone + PartialEq,
    I::CloseCause: Debug,
{
    type Destination = AnyActiveLinkPath;
    type LinkPathSendPlanner = EventLoggingPlanner<I>;
    /// What is published through the intake is not recorded.
    type Intake = RankedSendIntake<I>;

    fn intake(&self) -> RankedSendIntake<I> {
        self.inner.intake()
    }

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
            content: Vec::new(),
            close: None,
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

/// The ranked strategy's planner of one link path, recording, with the
/// driver's content it was given when it was last asked for a plan.
pub struct EventLoggingPlanner<I: SendStrategyTypes> {
    inner: RankedLinkPathSendPlanner<I>,
    index: usize,
    content: Vec<String>,
    close: Option<u64>,
}

impl<I: SendStrategyTypes> EventLoggingPlanner<I>
where
    I::SendIntents: Debug,
{
    /// Record what `driver` holds that it did not when last asked, and what
    /// it no longer holds.
    fn record_content(&mut self, driver: &DriverContent<I::SendIntents>) {
        let now: Vec<String> = driver
            .intents
            .iter()
            .map(|intent| intent_label(&format!("{intent:?}")))
            .collect();
        for label in &now {
            if !self.content.contains(label) {
                record(format!("path {}: content {label}", self.index));
            }
        }
        for label in &self.content {
            if !now.contains(label) {
                record(format!("path {}: gone {label}", self.index));
            }
        }
        self.content = now;
        let close = driver.close.map(|facts| facts.datagrams_received);
        if close != self.close {
            if let Some(count) = close {
                record(format!("path {}: close {count}", self.index));
            }
            self.close = close;
        }
    }
}

/// The intent a sum of intents holds, as its `Debug` form shows it inside
/// the `Inl` and `Inr` of the sum.
fn intent_label(debug: &str) -> String {
    let mut label = debug;
    loop {
        if let Some(inner) = label
            .strip_prefix("Inl(")
            .or_else(|| label.strip_prefix("Inr("))
            .and_then(|inner| inner.strip_suffix(')'))
        {
            label = inner;
        } else {
            return label.to_owned();
        }
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
    I::SendIntents: RankedIntent + Debug,
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
        driver: &'a DriverContent<I::SendIntents>,
        cx: &mut Context<'_>,
    ) -> Poll<PlannedDatagram<Self::Plan<'a>>> {
        ASKED.with(|asked| {
            let mut asked = asked.borrow_mut();
            if asked.len() <= self.index {
                asked.resize(self.index + 1, 0);
            }
            asked[self.index] += 1;
        });
        self.record_content(driver);
        if PLAN_NOTHING.with(Cell::get) {
            return Poll::Pending;
        }
        self.inner.poll_plan(&mut core.inner, driver, cx)
    }

    fn role_changed(
        &mut self,
        core: &mut Self::Core,
        role: LinkPathRoleKind,
        ended: &mut impl Extend<I::SendIntents>,
    ) {
        record(format!("path {}: role {role:?}", self.index));
        self.inner.role_changed(&mut core.inner, role, ended);
    }

    fn ended(self, core: &mut Self::Core, ended: &mut impl Extend<I::SendIntents>) {
        record(format!("path {}: ended", self.index));
        self.inner.ended(&mut core.inner, ended);
    }
}
