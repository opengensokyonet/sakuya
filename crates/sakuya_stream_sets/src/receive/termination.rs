//! Applying the decisions of the receive termination policy to a stream
//! receiver, after checking them against the
//! [policy contract](sakuya_stream_v1::receive::termination#contract).
use super::{Applied, Boundary, Destruction, StreamReceiver};
use core::convert::Infallible;
use core::fmt;
use sakuya_stream_v1::receive::flow_control::{ReceiveFlowControlPolicy, ReceiveFlowEvent};
use sakuya_stream_v1::receive::read::SharedTerminationReason;
use sakuya_stream_v1::receive::remote_reset::RemoteResetFacts;
use sakuya_stream_v1::receive::stop::StopError;
use sakuya_stream_v1::receive::termination::{
    BoundaryAction, BoundaryUpdate, ReceiveTerminationPolicy, ResetPresentation,
    TerminationDecision, TerminationEvent,
};
use sakuya_stream_v1::receive_buffer::StreamReceiveBuffer;
use sakuya_wire_v1::application_error::ApplicationErrorCode;
use sakuya_wire_v1::var_int::VarInt;
use snafu::{Report, Snafu, ensure};

/// A checked limit action, ready to apply.
enum Plan<R, X> {
    Nothing,
    Restrict {
        acceptance: Option<Boundary<R, X>>,
        delivery: Option<Boundary<R, X>>,
    },
    Destroy(Applied<R, X>),
}

/// Which of the two limits an update names.
#[derive(Clone, Copy)]
enum Limit {
    Acceptance,
    Delivery,
}

/// A checked decision, ready to apply.
struct DecisionPlan<R, X> {
    action: Plan<R, X>,
    install_stop: Option<ApplicationErrorCode>,
    reset_presentation: Option<ResetPresentation>,
}

/// A decision that violates the [policy contract](self#contract).
///
/// `X` is the change the triggering event may carry
/// ([`RemoteResetFacts::Change`]).
#[derive(Debug, Snafu)]
#[snafu(module(policy_violation))]
enum PolicyViolationError<X: fmt::Debug> {
    #[snafu(display(
        "receive termination policy violated its contract: destroys the receive buffer on {trigger:?} without a reset, a sent STOP request or a dropped reader"
    ))]
    DestroysWithoutBasis { trigger: TerminationEvent<X> },
    #[snafu(display(
        "receive termination policy violated its contract: restricts the receive buffer on {trigger:?} without a reset, a sent STOP request or a dropped reader"
    ))]
    RestrictsWithoutBasis { trigger: TerminationEvent<X> },
    #[snafu(display(
        "receive termination policy violated its contract: destroys the receive buffer on {trigger:?} while the prefix the peer still owes is undelivered"
    ))]
    DestroysOwedPrefix { trigger: TerminationEvent<X> },
    #[snafu(display(
        "receive termination policy violated its contract: restricts the receive buffer on {trigger:?} after delivery ended"
    ))]
    RestrictsAfterEnd { trigger: TerminationEvent<X> },
    #[snafu(display(
        "receive termination policy violated its contract: fixes the acceptance limit at {limit}, beyond the final size {final_size}"
    ))]
    AcceptanceBeyondFinalSize { limit: VarInt, final_size: VarInt },
    #[snafu(display(
        "receive termination policy violated its contract: fixes the delivery limit at {limit}, beyond the final size {final_size}"
    ))]
    DeliveryBeyondFinalSize { limit: VarInt, final_size: VarInt },
    #[snafu(display(
        "receive termination policy violated its contract: raises the fixed acceptance limit from {fixed} to {limit}"
    ))]
    RaisesFixedAcceptance { fixed: VarInt, limit: VarInt },
    #[snafu(display(
        "receive termination policy violated its contract: raises the fixed delivery limit from {fixed} to {limit}"
    ))]
    RaisesFixedDelivery { fixed: VarInt, limit: VarInt },
    #[snafu(display(
        "receive termination policy violated its contract: fixes the delivery limit at {limit} on {trigger:?}, inside the undelivered prefix the peer still owes up to {owed_end}"
    ))]
    DeliveryInsideOwedPrefix {
        limit: VarInt,
        trigger: TerminationEvent<X>,
        owed_end: VarInt,
    },
    #[snafu(display(
        "receive termination policy violated its contract: fixes the acceptance limit at {limit} on {trigger:?}, inside the unreceived prefix the peer still owes up to {owed_end}"
    ))]
    AcceptanceInsideOwedPrefix {
        limit: VarInt,
        trigger: TerminationEvent<X>,
        owed_end: VarInt,
    },
    #[snafu(display(
        "receive termination policy violated its contract: STOP request with code {code} on {trigger:?}"
    ))]
    Stop {
        code: ApplicationErrorCode,
        trigger: TerminationEvent<X>,
        source: StopError<Infallible>,
    },
    #[snafu(display(
        "receive termination policy violated its contract: STOP request with code {code} on {trigger:?} after the connection closed"
    ))]
    StopAfterConnectionClosed {
        code: ApplicationErrorCode,
        trigger: TerminationEvent<X>,
    },
}

/// The result of checking a decision against the
/// [policy contract](self#contract).
type Checked<T, X> = Result<T, PolicyViolationError<X>>;

impl<C, Lc, F> StreamReceiver<C, Lc, F>
where
    C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<F>,
    F: RemoteResetFacts,
{
    /// Checks a whole decision, then applies it.
    ///
    /// This is the single place where a policy's contract violation ends the
    /// operation: the check runs before anything changes.
    pub(super) fn apply_decision(
        &mut self,
        trigger: TerminationEvent<F::Change>,
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
        trigger: TerminationEvent<F::Change>,
        decision: TerminationDecision<C::Reason>,
    ) -> Checked<DecisionPlan<C::Reason, F::Change>, F::Change> {
        let TerminationDecision {
            action,
            stop,
            reset_presentation,
        } = decision;
        let action = self.check_action(action, trigger)?;
        let install_stop = match stop {
            Some(code) => match self.check_stop(code) {
                Ok(install) => install.then_some(code),
                Err(error) => {
                    return Err(match error.without_closed_connection() {
                        Ok(source) => PolicyViolationError::Stop {
                            code,
                            trigger,
                            source,
                        },
                        Err(_closed) => {
                            PolicyViolationError::StopAfterConnectionClosed { code, trigger }
                        }
                    });
                }
            },
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
        trigger: TerminationEvent<F::Change>,
    ) -> Checked<Plan<C::Reason, F::Change>, F::Change> {
        let ended = self.is_destroyed() || self.is_result_committed();
        match action {
            BoundaryAction::Keep => Ok(Plan::Nothing),
            BoundaryAction::Destroy { reason } => {
                if self.is_destroyed() {
                    return Ok(Plan::Nothing);
                }
                if !ended {
                    ensure!(
                        self.has_basis(),
                        policy_violation::DestroysWithoutBasisSnafu { trigger }
                    );
                    ensure!(
                        self.local_cancellation() || !self.owed_prefix_pending(),
                        policy_violation::DestroysOwedPrefixSnafu { trigger }
                    );
                }
                Ok(Plan::Destroy(Applied {
                    reason: SharedTerminationReason::new(reason),
                    trigger,
                }))
            }
            BoundaryAction::Restrict {
                acceptance,
                delivery,
                reason,
            } => {
                let acceptance = self.check_update(Limit::Acceptance, acceptance)?;
                let delivery = self.check_update(Limit::Delivery, delivery)?;
                if acceptance.is_none() && delivery.is_none() {
                    return Ok(Plan::Nothing);
                }
                ensure!(!ended, policy_violation::RestrictsAfterEndSnafu { trigger });
                ensure!(
                    self.has_basis(),
                    policy_violation::RestrictsWithoutBasisSnafu { trigger }
                );
                self.check_owed_prefix(acceptance, delivery, trigger)?;
                let reason = SharedTerminationReason::new(reason);
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
        limit_kind: Limit,
        update: BoundaryUpdate,
    ) -> Checked<Option<VarInt>, F::Change> {
        let BoundaryUpdate::Fix(limit) = update else {
            return Ok(None);
        };
        if let Some(final_size) = self.parts.final_size() {
            match limit_kind {
                Limit::Acceptance => ensure!(
                    limit <= final_size,
                    policy_violation::AcceptanceBeyondFinalSizeSnafu { limit, final_size }
                ),
                Limit::Delivery => ensure!(
                    limit <= final_size,
                    policy_violation::DeliveryBeyondFinalSizeSnafu { limit, final_size }
                ),
            }
        }
        let current = match limit_kind {
            Limit::Acceptance => &self.acceptance,
            Limit::Delivery => &self.delivery,
        };
        match current {
            Boundary::Following => Ok(Some(limit)),
            Boundary::Fixed { limit: fixed, .. } => {
                let fixed = *fixed;
                match limit_kind {
                    Limit::Acceptance => ensure!(
                        limit <= fixed,
                        policy_violation::RaisesFixedAcceptanceSnafu { fixed, limit }
                    ),
                    Limit::Delivery => ensure!(
                        limit <= fixed,
                        policy_violation::RaisesFixedDeliverySnafu { fixed, limit }
                    ),
                }
                Ok((limit < fixed).then_some(limit))
            }
        }
    }

    /// Whether a reset, a sent STOP request or a dropped reader allows
    /// restricting or destroying the receive buffer.
    fn has_basis(&self) -> bool {
        self.reset.is_some() || self.local_cancellation()
    }

    /// Checks that new limits leave alone the prefix the peer still owes,
    /// unless a local cancellation gave it up.
    fn check_owed_prefix(
        &self,
        acceptance: Option<VarInt>,
        delivery: Option<VarInt>,
        trigger: TerminationEvent<F::Change>,
    ) -> Checked<(), F::Change> {
        let Some(reset) = self.reset else {
            return Ok(());
        };
        let owed_end = reset.owed_end();
        if self.local_cancellation() || owed_end == VarInt::ZERO {
            return Ok(());
        }
        if let Some(limit) = delivery {
            ensure!(
                limit >= owed_end || self.parts.delivered_end() >= owed_end,
                policy_violation::DeliveryInsideOwedPrefixSnafu {
                    limit,
                    trigger,
                    owed_end,
                }
            );
        }
        if let Some(limit) = acceptance {
            ensure!(
                limit >= owed_end || self.received.covers(limit..owed_end),
                policy_violation::AcceptanceInsideOwedPrefixSnafu {
                    limit,
                    trigger,
                    owed_end,
                }
            );
        }
        Ok(())
    }

    /// Whether a local cancellation allows giving up the prefix the peer
    /// still owes.
    fn local_cancellation(&self) -> bool {
        self.stop_sent() || self.is_reader_dropped()
    }

    fn owed_prefix_pending(&self) -> bool {
        self.reset
            .is_some_and(|reset| self.parts.delivered_end() < reset.owed_end())
    }
}
