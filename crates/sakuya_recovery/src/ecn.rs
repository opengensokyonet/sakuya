//! Which ECN codepoint a link path sends (RFC 9000 §13.4 and RFC 9002
//! Appendix A.4).
//!
//! Validation is fixed and lives with the caller: it checks the counts each
//! ACK reports, and when validation fails it stops marking (RFC 9000
//! §13.4.2.2, MUST) without asking. What is replaceable is the
//! [`EcnPolicy`]: which codepoint to mark with, how long the test lasts,
//! and whether to validate again after a failure. It is implemented by the
//! same value as the congestion controller, because the codepoint and the
//! algorithm go together: an L4S queue treats ECT(1) as L4S traffic.
use crate::{checked_duration_since, rtt::RttEstimate};
use core::{ops::Sub, time::Duration};
use sakuya_link::EcnMarking;

/// The ECN policy of a link path.
pub trait EcnPolicy<I> {
    /// The marking of the next datagram, asked at the start of each one.
    ///
    /// It is not asked while validation has failed, while another link path
    /// of the same packet number space still has marked packets in flight,
    /// or when the link cannot mark: those datagrams are Not-ECT.
    fn marking(&mut self, context: &EcnContext<I>) -> EcnMarking;

    /// Validation has failed: whether to start it again (RFC 9000
    /// §13.4.2.2, MAY). `true` makes the counts at this moment the new
    /// baseline and the outcome [`Unvalidated`](EcnValidationOutcome).
    fn wants_revalidation(&mut self, context: &EcnContext<I>) -> bool;
}

impl<I, T: EcnPolicy<I> + ?Sized> EcnPolicy<I> for &mut T {
    fn marking(&mut self, context: &EcnContext<I>) -> EcnMarking {
        (**self).marking(context)
    }

    fn wants_revalidation(&mut self, context: &EcnContext<I>) -> bool {
        (**self).wants_revalidation(context)
    }
}

/// Where ECN validation of a link path stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EcnValidationOutcome {
    /// No ACK has confirmed the markings yet.
    Unvalidated,
    /// An ACK confirmed marked packets: the path and the peer carry ECN.
    Capable,
    /// Validation failed: marking has stopped.
    Failed,
}

/// The facts an [`EcnPolicy`] decides from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcnContext<I> {
    /// The instant of the poll.
    pub now: I,
    /// Where validation stands.
    pub outcome: EcnValidationOutcome,
    /// How many marked packets were sent since this test started.
    pub marked_since_start: u64,
    /// When this test started.
    pub started_at: I,
    /// The RTT estimate of the link path.
    pub rtt: RttEstimate,
    /// The probe timeout of the link path without backoff.
    pub pto: Duration,
}

/// How many marked packets the test sends at most (RFC 9000 §13.4.2).
pub const ECN_TESTING_PACKETS: u64 = 10;

/// How many probe timeouts the test lasts at most (RFC 9000 §13.4.2).
pub const ECN_TESTING_PTOS: u32 = 3;

/// The marking of the ECN test RFC 9000 §13.4.2 suggests, with ECT(0).
///
/// While validation is pending it marks ECT(0) until
/// [`ECN_TESTING_PACKETS`] marked packets were sent or
/// [`ECN_TESTING_PTOS`] probe timeouts passed since the test started,
/// whichever comes first, and Not-ECT after that; once capable it marks
/// ECT(0). The packets counted are QUIC packets, so the packets coalesced
/// into one datagram count separately.
pub fn ect0_testing_marking<I>(context: &EcnContext<I>) -> EcnMarking
where
    I: Ord + Copy + Sub<Output = Duration>,
{
    match context.outcome {
        EcnValidationOutcome::Capable => EcnMarking::Ect0,
        EcnValidationOutcome::Failed => EcnMarking::NotEct,
        EcnValidationOutcome::Unvalidated => {
            let elapsed =
                checked_duration_since(context.now, context.started_at).unwrap_or(Duration::ZERO);
            let testing = context.marked_since_start < ECN_TESTING_PACKETS
                && elapsed < context.pto.saturating_mul(ECN_TESTING_PTOS);
            if testing {
                EcnMarking::Ect0
            } else {
                EcnMarking::NotEct
            }
        }
    }
}

#[cfg(test)]
mod tests;
