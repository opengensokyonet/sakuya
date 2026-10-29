//! The receive termination policy: local delivery decisions at the end of a
//! stream's receive direction.
//!
//! On each [`TerminationEvent`] the policy returns a [`TerminationDecision`]:
//! a [`BoundaryAction`] — keep, restrict the receive buffer, or destroy it —
//! optionally a STOP request and a reset presentation. The stream receive
//! component checks the whole decision against the current state, then
//! applies it in one go. The shape of the decision is provisional.
//!
//! # Contract
//!
//! A decision must be valid for the state the policy was shown, by the
//! permissions below. A decision that is not violates this contract: the
//! stream receive component detects it before anything changes and panics.
//! It is a defect of the policy, not clamped and not turned into a protocol
//! error.
//!
//! # Permissions
//!
//! - Restricting or destroying needs a basis in the current state: a reset
//!   was received, the STOP request was actually sent, or the reader was
//!   dropped. Installing a STOP request alone is no basis.
//! - A fixed limit can stay or tighten, never rise, and never exceed a known
//!   final size; a following limit can be fixed at any legal offset.
//! - Once the buffer is destroyed, a read result is committed or the
//!   connection failed, only keeping and destroying (as clean-up) remain.
//! - While a `RESET_STREAM_AT` reliable prefix still needs delivery or gap
//!   filling, breaking it — fixing the delivery limit below it, fixing the
//!   acceptance limit below a part of it not yet received, or destroying —
//!   needs a local cancellation: the STOP request was sent or the reader was
//!   dropped.
//!
//! # Effects
//!
//! A strictly tighter limit, or a following limit becoming fixed, records
//! the decision's reason and the event as its trigger; an unchanged limit
//! keeps its earlier reason. Tightening the delivery limit releases held data
//! beyond it; tightening the acceptance limit only stops keeping new payload.
//! Neither changes the accounted end, the final size or flow control credit,
//! and a limit below the read position does not take back delivered data.
//!
//! The destruction forced when the reader is dropped or a terminal error is
//! delivered does not ask the policy.
use super::{
    Applied, Boundary, BoundaryMode, Destruction, StreamReceiver,
    flow_control::ReceiveFlowControlPolicy, flow_control::ReceiveFlowEvent, read::RemoteReset,
    stop::StopError,
};
use crate::receive_buffer::ReceiveBuffer;
use core::{convert::Infallible, fmt};
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::var_int::VarInt;
use snafu::{Report, ResultExt, Snafu, ensure};

/// The events a receive termination policy observes.
///
/// An event is delivered after the fact it reports took effect. The same
/// value names the trigger of a local termination in
/// [`ReadError::LocalTermination`](super::read::ReadError::LocalTermination).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TerminationEvent {
    /// The first `RESET_STREAM` or `RESET_STREAM_AT` was received.
    RemoteReset,
    /// A later reset lowered the effective reliable size.
    ReliablePrefixLowered,
    /// Every byte of `[0, final_size)` has been received.
    DataComplete,
    /// A local STOP request was installed.
    StopRequested,
    /// The installed STOP request was actually sent.
    StopSent,
    /// The stream reader was dropped; the receive buffer is already
    /// destroyed.
    ReaderDropped,
    /// A read committed the end of stream or a terminal error.
    ReadResultCommitted,
    /// The connection closed, or input of the stream violated the protocol.
    ConnectionClosed,
}

/// The state a receive termination policy decides on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TerminationView {
    /// The accounted end.
    pub accounted_end: VarInt,
    /// The final size, if known.
    pub final_size: Option<VarInt>,
    /// How far data has been delivered to the application.
    pub delivered_end: VarInt,
    /// Whether every byte of `[0, final_size)` has been received.
    pub fully_received: bool,
    /// The reset facts, if a reset was received.
    pub reset: Option<RemoteReset>,
    /// The data acceptance limit.
    pub acceptance: BoundaryMode,
    /// The delivery limit.
    pub delivery: BoundaryMode,
    /// Whether the receive buffer is destroyed.
    pub destroyed: bool,
    /// Whether a read result has been committed.
    pub read_result_committed: bool,
    /// The code of the installed STOP request, if any.
    pub stop_code: Option<ApplicationErrorCode>,
    /// Whether the installed STOP request was sent.
    pub stop_sent: bool,
    /// Whether a new STOP request would be installed.
    pub stop_allowed: bool,
    /// Whether the reader was dropped.
    pub reader_dropped: bool,
    /// Whether the connection failed.
    pub connection_failed: bool,
}

/// Whether a completely delivered stream that the peer reset ends with the
/// reset or with a normal end of stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ResetPresentation {
    /// Report the reset, marked complete ([RFC 9000 §3.2] allows either).
    ///
    /// [RFC 9000 §3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.2
    #[default]
    Report,
    /// Suppress the reset and end the stream normally.
    Suppress,
}

/// The update of one local delivery limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BoundaryUpdate {
    /// Leave the limit as it is.
    Keep,
    /// Fix the limit at this absolute offset.
    Fix(VarInt),
}

/// A limit action on the receive buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoundaryAction<R> {
    /// Change nothing.
    Keep,
    /// Fix or tighten the data acceptance limit and the delivery limit
    /// (`restrict`).
    Restrict {
        /// The update of the data acceptance limit.
        acceptance: BoundaryUpdate,
        /// The update of the delivery limit.
        delivery: BoundaryUpdate,
        /// The local reason, recorded for each limit that changes.
        reason: R,
    },
    /// Destroy the receive buffer: release all held data and end delivery.
    Destroy {
        /// The local reason.
        reason: R,
    },
}

/// A receive termination policy's answer to one event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminationDecision<R> {
    /// The limit action.
    pub action: BoundaryAction<R>,
    /// A STOP request to install, with its application error code. It must
    /// be one the protocol allows ([`TerminationView::stop_allowed`]) or the
    /// request already installed.
    pub stop: Option<ApplicationErrorCode>,
    /// A new reset presentation; `None` keeps the current one. It has no
    /// effect once a read result is committed.
    pub reset_presentation: Option<ResetPresentation>,
}

impl<R> TerminationDecision<R> {
    /// Changes nothing.
    pub const fn keep() -> Self {
        Self::new(BoundaryAction::Keep)
    }

    /// Takes `action` and nothing else.
    pub const fn new(action: BoundaryAction<R>) -> Self {
        Self {
            action,
            stop: None,
            reset_presentation: None,
        }
    }

    /// Also installs a STOP request with `code`.
    pub fn with_stop(mut self, code: ApplicationErrorCode) -> Self {
        self.stop = Some(code);
        self
    }

    /// Also sets the reset presentation.
    pub fn with_reset_presentation(mut self, presentation: ResetPresentation) -> Self {
        self.reset_presentation = Some(presentation);
        self
    }
}

/// Local delivery decisions of one stream's receive direction.
///
/// Implementations follow the [contract](self#contract).
pub trait ReceiveTerminationPolicy {
    /// The local reason a policy records with its actions.
    ///
    /// Read errors report it repeatedly, so it is a shared handle: cloning
    /// shares the reason. It can be an `Rc` or `Arc` of a richer reason, or a
    /// small `Copy` value.
    type Reason: Clone + fmt::Debug;

    /// Decides on `event`, given the state after it.
    fn on_termination_event(
        &mut self,
        event: TerminationEvent,
        view: &TerminationView,
    ) -> TerminationDecision<Self::Reason>;
}

/// A receive termination policy that keeps both local limits following.
///
/// - It keeps the current local choices when a STOP request is installed or
///   sent.
/// - After a reset it keeps both limits following, so late data within the
///   unabandoned range can still complete the stream; reading stops at the
///   first gap beyond the reliable prefix. A completely delivered stream that
///   was reset reports the reset, marked complete.
/// - When the reader is dropped and the protocol still allows a STOP request
///   and none is installed, it requests one with `abandon_code`; an installed
///   request keeps its code.
///
/// It never restricts or destroys by itself, so its reason type is
/// uninhabited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FollowingTermination {
    abandon_code: ApplicationErrorCode,
}

/// The receive termination policy of the default receive composition.
pub type DefaultReceiveTermination = FollowingTermination;

impl FollowingTermination {
    /// Creates the policy with the application error code for STOP requests
    /// made when the reader is dropped.
    pub fn new(abandon_code: ApplicationErrorCode) -> Self {
        Self { abandon_code }
    }

    /// The application error code for STOP requests made when the reader is
    /// dropped.
    pub fn abandon_code(&self) -> ApplicationErrorCode {
        self.abandon_code
    }
}

impl ReceiveTerminationPolicy for FollowingTermination {
    type Reason = Infallible;

    fn on_termination_event(
        &mut self,
        event: TerminationEvent,
        view: &TerminationView,
    ) -> TerminationDecision<Infallible> {
        match event {
            TerminationEvent::RemoteReset => {
                TerminationDecision::keep().with_reset_presentation(ResetPresentation::Report)
            }
            TerminationEvent::ReaderDropped if view.stop_allowed => {
                TerminationDecision::keep().with_stop(self.abandon_code)
            }
            _ => TerminationDecision::keep(),
        }
    }
}

/// A checked limit action, ready to apply.
enum Plan<R> {
    Nothing,
    Restrict {
        acceptance: Option<Boundary<R>>,
        delivery: Option<Boundary<R>>,
    },
    Destroy(Applied<R>),
}

/// A checked decision, ready to apply.
struct DecisionPlan<R> {
    action: Plan<R>,
    install_stop: Option<ApplicationErrorCode>,
    reset_presentation: Option<ResetPresentation>,
}

/// A decision that violates the [policy contract](self#contract).
#[derive(Debug, Snafu)]
#[snafu(module(policy_violation))]
enum PolicyViolation {
    #[snafu(display(
        "receive termination policy violated its contract: {what} the receive buffer on {trigger:?} without a reset, a sent STOP request or a dropped reader"
    ))]
    NoBasis {
        what: &'static str,
        trigger: TerminationEvent,
    },
    #[snafu(display(
        "receive termination policy violated its contract: destroys the receive buffer on {trigger:?} while the reliable prefix is undelivered"
    ))]
    DestroysReliablePrefix { trigger: TerminationEvent },
    #[snafu(display(
        "receive termination policy violated its contract: restricts the receive buffer on {trigger:?} after delivery ended"
    ))]
    RestrictsAfterEnd { trigger: TerminationEvent },
    #[snafu(display(
        "receive termination policy violated its contract: fixes the {name} limit at {limit}, beyond the final size {final_size}"
    ))]
    BeyondFinalSize {
        name: &'static str,
        limit: VarInt,
        final_size: VarInt,
    },
    #[snafu(display(
        "receive termination policy violated its contract: raises the fixed {name} limit from {fixed} to {limit}"
    ))]
    RaisesFixedLimit {
        name: &'static str,
        fixed: VarInt,
        limit: VarInt,
    },
    #[snafu(display(
        "receive termination policy violated its contract: fixes the delivery limit at {limit} on {trigger:?}, inside the undelivered reliable prefix {reliable_size}"
    ))]
    DeliveryInsideReliablePrefix {
        limit: VarInt,
        trigger: TerminationEvent,
        reliable_size: VarInt,
    },
    #[snafu(display(
        "receive termination policy violated its contract: fixes the acceptance limit at {limit} on {trigger:?}, inside the unreceived reliable prefix {reliable_size}"
    ))]
    AcceptanceInsideReliablePrefix {
        limit: VarInt,
        trigger: TerminationEvent,
        reliable_size: VarInt,
    },
    #[snafu(display(
        "receive termination policy violated its contract: STOP request with code {code} on {trigger:?}"
    ))]
    Stop {
        code: ApplicationErrorCode,
        trigger: TerminationEvent,
        source: StopError,
    },
}

impl<C> StreamReceiver<C>
where
    C: ReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy,
{
    /// Checks a whole decision, then applies it.
    ///
    /// This is the single place where a policy's contract violation ends the
    /// operation: the check runs before anything changes.
    pub(super) fn apply_decision(
        &mut self,
        trigger: TerminationEvent,
        decision: TerminationDecision<C::Reason>,
    ) {
        let plan = match self.check_decision(trigger, decision) {
            Ok(plan) => plan,
            Err(violation) => panic!("{}", Report::from_error(violation)),
        };
        if let Some(presentation) = plan.reset_presentation
            && !self.is_result_committed()
        {
            self.reset_presentation = presentation;
        }
        match plan.action {
            Plan::Nothing => {}
            Plan::Destroy(applied) => self.destroy_buffer(Destruction::Policy(applied)),
            Plan::Restrict {
                acceptance,
                delivery,
            } => {
                if let Some(acceptance) = acceptance {
                    self.acceptance = acceptance;
                }
                if let Some(delivery) = delivery {
                    let limit = delivery.limit();
                    self.delivery = delivery;
                    self.parts.release_from(limit);
                }
                self.notify_flow(ReceiveFlowEvent::BoundaryChanged);
            }
        }
        if let Some(code) = plan.install_stop {
            self.install_stop(code);
        }
    }

    /// Checks a whole decision against the
    /// [policy contract](self#contract) and the current state.
    fn check_decision(
        &self,
        trigger: TerminationEvent,
        decision: TerminationDecision<C::Reason>,
    ) -> Result<DecisionPlan<C::Reason>, PolicyViolation> {
        let TerminationDecision {
            action,
            stop,
            reset_presentation,
        } = decision;
        let action = self.check_action(action, trigger)?;
        let install_stop = match stop {
            Some(code) => self
                .check_stop(code)
                .context(policy_violation::StopSnafu { code, trigger })?
                .then_some(code),
            None => None,
        };
        Ok(DecisionPlan {
            action,
            install_stop,
            reset_presentation,
        })
    }

    fn check_action(
        &self,
        action: BoundaryAction<C::Reason>,
        trigger: TerminationEvent,
    ) -> Result<Plan<C::Reason>, PolicyViolation> {
        let ended = self.is_destroyed() || self.is_result_committed();
        match action {
            BoundaryAction::Keep => Ok(Plan::Nothing),
            BoundaryAction::Destroy { reason } => {
                if self.is_destroyed() {
                    return Ok(Plan::Nothing);
                }
                if !ended {
                    self.check_basis("destroys", trigger)?;
                    ensure!(
                        self.local_cancellation() || !self.reliable_prefix_pending(),
                        policy_violation::DestroysReliablePrefixSnafu { trigger }
                    );
                }
                Ok(Plan::Destroy(Applied { reason, trigger }))
            }
            BoundaryAction::Restrict {
                acceptance,
                delivery,
                reason,
            } => {
                let acceptance = self.check_update(&self.acceptance, acceptance, "acceptance")?;
                let delivery = self.check_update(&self.delivery, delivery, "delivery")?;
                if acceptance.is_none() && delivery.is_none() {
                    return Ok(Plan::Nothing);
                }
                ensure!(!ended, policy_violation::RestrictsAfterEndSnafu { trigger });
                self.check_basis("restricts", trigger)?;
                self.check_reliable_prefix(acceptance, delivery, trigger)?;
                let fixed = |limit| Boundary::Fixed {
                    limit,
                    applied: Applied {
                        reason: reason.clone(),
                        trigger,
                    },
                };
                Ok(Plan::Restrict {
                    acceptance: acceptance.map(fixed),
                    delivery: delivery.map(fixed),
                })
            }
        }
    }

    /// The new fixed value of a limit, if the update changes it.
    fn check_update(
        &self,
        current: &Boundary<C::Reason>,
        update: BoundaryUpdate,
        name: &'static str,
    ) -> Result<Option<VarInt>, PolicyViolation> {
        let BoundaryUpdate::Fix(limit) = update else {
            return Ok(None);
        };
        if let Some(final_size) = self.parts.final_size() {
            ensure!(
                limit <= final_size,
                policy_violation::BeyondFinalSizeSnafu {
                    name,
                    limit,
                    final_size,
                }
            );
        }
        match current {
            Boundary::Following => Ok(Some(limit)),
            Boundary::Fixed { limit: fixed, .. } => {
                ensure!(
                    limit <= *fixed,
                    policy_violation::RaisesFixedLimitSnafu {
                        name,
                        fixed: *fixed,
                        limit,
                    }
                );
                Ok((limit < *fixed).then_some(limit))
            }
        }
    }

    fn check_basis(
        &self,
        what: &'static str,
        trigger: TerminationEvent,
    ) -> Result<(), PolicyViolation> {
        ensure!(
            self.reset.is_some() || self.local_cancellation(),
            policy_violation::NoBasisSnafu { what, trigger }
        );
        Ok(())
    }

    fn check_reliable_prefix(
        &self,
        acceptance: Option<VarInt>,
        delivery: Option<VarInt>,
        trigger: TerminationEvent,
    ) -> Result<(), PolicyViolation> {
        let Some(reset) = self.reset else {
            return Ok(());
        };
        if self.local_cancellation() || reset.reliable_size == VarInt::ZERO {
            return Ok(());
        }
        let reliable_size = reset.reliable_size;
        if let Some(limit) = delivery {
            ensure!(
                limit >= reliable_size || self.parts.delivered_end() >= reliable_size,
                policy_violation::DeliveryInsideReliablePrefixSnafu {
                    limit,
                    trigger,
                    reliable_size,
                }
            );
        }
        if let Some(limit) = acceptance {
            ensure!(
                limit >= reliable_size || self.parts.is_received(limit..reliable_size),
                policy_violation::AcceptanceInsideReliablePrefixSnafu {
                    limit,
                    trigger,
                    reliable_size,
                }
            );
        }
        Ok(())
    }

    /// Whether a local cancellation allows giving up a reliable prefix.
    fn local_cancellation(&self) -> bool {
        self.stop_sent() || self.is_reader_dropped()
    }

    fn reliable_prefix_pending(&self) -> bool {
        self.reset
            .is_some_and(|reset| self.parts.delivered_end() < reset.reliable_size)
    }
}
