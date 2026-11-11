//! What makes the replaceable parts of a link path, and lends its
//! congestion access.
//!
//! A connection has one [`RecoveryFactory`]. When a link path is built
//! (the first one of the connection, and one whose new address was just
//! validated) the factory makes its RTT estimate, the part of its
//! congestion control that the link path stores, and its datagram size
//! probing policy; they are never replaced afterward. A link path that only
//! changed ports keeps them. Each connection's factory is made from a
//! [`RecoveryFactory::Config`], checked when that is built, so neither
//! making the factory nor making the parts can fail.
//!
//! Every use of a link path's congestion state (sending, an ACK, an expiry
//! of the probe timeout) goes through [`LendCongestion`]: the factory gets
//! the part of this link path and a read-only view of the others, and
//! lends a value that is the congestion controller, pacer, probe timeout
//! policy and ECN policy of this link path. A factory for QUIC version 1
//! alone lends the part as it is; a coupled one combines it with the
//! others.
//!
//! [`NewRenoRecoveryFactory`] is the factory sakuya provides.
use crate::{
    congestion::{
        CongestionController, InitialWindow,
        new_reno::{NewReno, NewRenoConfig},
    },
    ecn::EcnPolicy,
    pacing::{PacedCongestionController, Pacer, TokenBucketPacer, TokenBucketPacerConfig},
    pmtu::{BinarySearchPmtuPolicy, BinarySearchPmtuPolicyConfig, PmtuPolicy},
    pto::PtoPolicy,
    rtt::{INITIAL_RTT, Rfc9002RttEstimator, RttEstimator},
};
use core::{
    marker::PhantomData,
    ops::{Add, Sub},
    time::Duration,
};
use sakuya_link::{Link, MIN_DATAGRAM_SIZE};
use snafu::{Snafu, ensure};

/// Makes the replaceable parts of each link path of one connection.
pub trait RecoveryFactory<L: Link>: Sized {
    /// The configuration a factory is made from, with handles to anything
    /// shared across connections. It is checked when it is built, so
    /// [`new`](Self::new) cannot fail.
    type Config: Clone;
    /// Where acknowledgments come back from, as the RTT estimate sees it.
    type Via;
    /// The RTT estimate.
    type Rtt: RttEstimator<L::Instant, Via = Self::Via>;
    /// The part of congestion control the link path stores: for QUIC
    /// version 1 alone, the controller itself.
    type CongestionPart;
    /// The datagram size probing policy.
    type Pmtu: PmtuPolicy<L>;

    /// The factory of a new connection. State of the connection as a
    /// whole, such as the coordination of coupled congestion control,
    /// starts empty.
    fn new(config: &Self::Config) -> Self;

    /// The parts of a link path over `link`.
    ///
    /// `initial_rtt` is the interval between sending a PATH_CHALLENGE and
    /// receiving its PATH_RESPONSE on the same link path, for a link path
    /// whose new address was validated (RFC 9002 §6.2.2, MAY); `None` for
    /// the first link path, or when the response came back over another
    /// one. It is not a sample: it sets the smoothed RTT and the variation
    /// only.
    fn create(
        &mut self,
        link: &L,
        initial_rtt: Option<Duration>,
    ) -> (Self::Rtt, Self::CongestionPart, Self::Pmtu);
}

/// Lends the congestion access of one link path.
///
/// `I` is the type of instants; `Others` is the read-only view of the other
/// link paths.
pub trait LendCongestion<I, Others> {
    /// The part of the link path's congestion control that it stores.
    type Part;
    /// The access lent for one use.
    type Access<'a>: CongestionController<I> + Pacer<I> + PtoPolicy<I> + EcnPolicy<I>
    where
        Self: 'a,
        Others: 'a;

    /// The access of the link path whose part is `this`.
    fn lend<'a>(&'a mut self, this: &'a mut Self::Part, others: &'a Others) -> Self::Access<'a>;

    /// The earliest deadline of the access [`lend`](Self::lend) would give
    /// for `this`: the next release of its pacer, and any instant its probe
    /// timeout policy sets apart from the probe timeout.
    ///
    /// It reads the part and the factory only, not the other link paths:
    /// a deadline is the state of the link path's own value, which the
    /// events of each lend leave in the part.
    fn next_deadline(&self, this: &Self::Part) -> Option<I>;
}

/// The congestion control a [`NewRenoRecoveryFactory`] makes for each link
/// path: NewReno with a token bucket pacer.
pub type PacedNewReno<I> = PacedCongestionController<NewReno<I>, TokenBucketPacer<I>>;

/// The configuration of a [`NewRenoRecoveryFactory`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewRenoRecoveryFactoryConfig {
    initial_rtt: Duration,
    new_reno: NewRenoConfig,
    pacer: TokenBucketPacerConfig,
    pmtu: BinarySearchPmtuPolicyConfig,
}

impl NewRenoRecoveryFactoryConfig {
    /// The configuration given. `initial_rtt` is the RTT a link path starts
    /// from when it has no measured initial RTT.
    ///
    /// # Errors
    ///
    /// [`PacerInitialWindowMismatchError`] if the pacer's initial window is
    /// not NewReno's: the pacer allows at least the controller's initial
    /// window in a burst.
    pub fn new(
        initial_rtt: Duration,
        new_reno: NewRenoConfig,
        pacer: TokenBucketPacerConfig,
        pmtu: BinarySearchPmtuPolicyConfig,
    ) -> Result<Self, PacerInitialWindowMismatchError> {
        ensure!(
            pacer.initial_window() == new_reno.initial_window(),
            PacerInitialWindowMismatchSnafu {
                pacer: pacer.initial_window(),
                congestion_controller: new_reno.initial_window(),
            }
        );
        Ok(Self {
            initial_rtt,
            new_reno,
            pacer,
            pmtu,
        })
    }

    /// The values RFC 9002 recommends, with the defaults of the pacer and
    /// of the probing policy, for a clock whose timers fire with a
    /// precision of `timer_granularity`.
    pub fn recommended(timer_granularity: Duration) -> Self {
        Self {
            initial_rtt: INITIAL_RTT,
            new_reno: NewRenoConfig::RECOMMENDED,
            pacer: TokenBucketPacerConfig::recommended(timer_granularity),
            pmtu: BinarySearchPmtuPolicyConfig::RECOMMENDED,
        }
    }
}

/// The initial windows of the pacer and of the congestion controller
/// differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "pacer's initial window {pacer:?} differs from the congestion controller's {congestion_controller:?}"
))]
pub struct PacerInitialWindowMismatchError {
    pacer: InitialWindow,
    congestion_controller: InitialWindow,
}

impl PacerInitialWindowMismatchError {
    /// The pacer's initial window.
    pub const fn pacer(&self) -> InitialWindow {
        self.pacer
    }

    /// The congestion controller's initial window.
    pub const fn congestion_controller(&self) -> InitialWindow {
        self.congestion_controller
    }
}

/// A recovery factory for QUIC version 1 alone: RTT estimates as RFC 9002
/// computes them ([`Rfc9002RttEstimator`]), NewReno paced by a token bucket
/// ([`PacedNewReno`]), and binary search probing
/// ([`BinarySearchPmtuPolicy`]).
///
/// It lends a link path's part as it is, whatever the other link paths
/// are. NewReno starts from the initial window of 1200-byte datagrams; the
/// caller tells it the size in use at the first datagram.
#[derive(Debug)]
pub struct NewRenoRecoveryFactory<Via> {
    config: NewRenoRecoveryFactoryConfig,
    via: PhantomData<fn() -> Via>,
}

impl<L, Via> RecoveryFactory<L> for NewRenoRecoveryFactory<Via>
where
    L: Link,
    L::Instant: Ord + Copy + Add<Duration, Output = L::Instant> + Sub<Output = Duration>,
{
    type Config = NewRenoRecoveryFactoryConfig;
    type Via = Via;
    type Rtt = Rfc9002RttEstimator<Via>;
    type CongestionPart = PacedNewReno<L::Instant>;
    type Pmtu = BinarySearchPmtuPolicy<L::Instant>;

    fn new(config: &NewRenoRecoveryFactoryConfig) -> Self {
        Self {
            config: *config,
            via: PhantomData,
        }
    }

    fn create(
        &mut self,
        _link: &L,
        initial_rtt: Option<Duration>,
    ) -> (Self::Rtt, Self::CongestionPart, Self::Pmtu) {
        let config = &self.config;
        (
            Rfc9002RttEstimator::new(initial_rtt.unwrap_or(config.initial_rtt)),
            PacedCongestionController::new(
                NewReno::new(config.new_reno, MIN_DATAGRAM_SIZE),
                TokenBucketPacer::new(config.pacer),
            ),
            BinarySearchPmtuPolicy::new(config.pmtu),
        )
    }
}

impl<I, Others, Via> LendCongestion<I, Others> for NewRenoRecoveryFactory<Via>
where
    I: Ord + Copy + Add<Duration, Output = I> + Sub<Output = Duration> + 'static,
{
    type Part = PacedNewReno<I>;
    type Access<'a>
        = &'a mut PacedNewReno<I>
    where
        Self: 'a,
        Others: 'a;

    fn lend<'a>(
        &'a mut self,
        this: &'a mut PacedNewReno<I>,
        _others: &'a Others,
    ) -> Self::Access<'a> {
        this
    }

    /// The next release of the pacer: the probe timeout policy of NewReno
    /// sets no instant of its own.
    fn next_deadline(&self, this: &PacedNewReno<I>) -> Option<I> {
        Pacer::next_release(this)
    }
}

#[cfg(test)]
mod tests;
