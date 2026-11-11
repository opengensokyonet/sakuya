//! Loss recovery, congestion control and datagram size probing for sakuya
//! ([RFC 9002], and RFC 9000 §14 for datagram sizes).
//!
//! Each link path of a connection has one RTT estimate, one congestion
//! controller with its pacer, and one datagram size probing policy. This
//! crate holds what can be replaced of them, as traits, with the
//! implementations sakuya provides, and the rules of the protocol that no
//! implementation may change, as functions:
//!
//! - [`rtt`]: the RTT estimate ([`rtt::RttEstimator`]) and the rules that
//!   turn an acknowledgment into a sample ([`rtt::RttSample`]).
//! - [`congestion`]: the congestion controller
//!   ([`congestion::CongestionController`]) and NewReno
//!   ([`congestion::new_reno::NewReno`]).
//! - [`pacing`]: the pacer ([`pacing::Pacer`]), the combinator that gives a
//!   window-only controller a pacer, and a token bucket pacer.
//! - [`pto`]: what to do when the probe timeout expires
//!   ([`pto::PtoPolicy`]) and its duration.
//! - [`ecn`]: which ECN codepoint to send ([`ecn::EcnPolicy`]).
//! - [`pmtu`]: datagram size probing ([`pmtu::PmtuPolicy`]) and a binary
//!   search policy.
//! - [`loss`] and [`persistent_congestion`]: the thresholds that declare a
//!   packet lost and the test for persistent congestion.
//! - [`factory`]: what makes the replaceable parts of a link path
//!   ([`factory::RecoveryFactory`]) and lends its congestion access
//!   ([`factory::LendCongestion`]).
//!
//! The congestion controller, the pacer, the probe timeout policy and the
//! ECN policy of a link path are one value: each is a trait, and a link path
//! requires its value to implement all four.
//!
//! Nothing here reads a clock. Instants are a type parameter `I` that the
//! caller chooses; code that measures time between two instants requires
//! `I: Ord + Sub<Output = Duration>` and subtracts only after comparing, with
//! [`checked_duration_since`]. Byte counts are `usize`.
//!
//! [RFC 9002]: https://www.rfc-editor.org/rfc/rfc9002.html
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::{ops::Sub, time::Duration};

pub mod congestion;
pub mod ecn;
pub mod factory;
pub mod loss;
pub mod pacing;
pub mod packet_number_space;
pub mod persistent_congestion;
pub mod pmtu;
pub mod pto;
pub mod ratio;
pub mod rtt;

/// The time from `earlier` to `later`; `None` if `later` is before
/// `earlier`.
///
/// It compares before it subtracts, so the subtraction of `I` is only used
/// where it cannot go below zero.
pub fn checked_duration_since<I>(later: I, earlier: I) -> Option<Duration>
where
    I: Ord + Sub<Output = Duration>,
{
    (later >= earlier).then(|| later - earlier)
}

#[cfg(test)]
mod tests {
    use super::checked_duration_since;
    use core::time::Duration;

    #[test]
    fn a_later_instant_gives_the_time_between() {
        let earlier = Duration::from_millis(10);
        let later = Duration::from_millis(25);
        assert_eq!(
            checked_duration_since(later, earlier),
            Some(Duration::from_millis(15))
        );
        assert_eq!(checked_duration_since(later, later), Some(Duration::ZERO));
    }

    #[test]
    fn an_earlier_instant_gives_none() {
        // `Duration`'s own subtraction would panic here.
        let earlier = Duration::from_millis(10);
        let later = Duration::from_millis(25);
        assert_eq!(checked_duration_since(earlier, later), None);
    }
}
