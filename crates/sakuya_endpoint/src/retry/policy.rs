use std::{net::SocketAddr, num::NonZeroU32, num::NonZeroUsize, sync::Arc};

use snafu::{Snafu, ensure};

use crate::address_token::NewTokenAddress;

/// Decides whether an endpoint answers an Initial packet with a stateless
/// Retry before it keeps any state for the connection attempt.
///
/// The endpoint asks the policy only when the protocol allows a Retry: the
/// packet carries no valid Retry token (a client accepts one Retry per
/// attempt, RFC 9000 §17.2.5.2), the first packet of the datagram is an
/// Initial rather than a 0-RTT packet, and the peer is a [`SocketAddr`], so
/// that a Retry token can be checked against it. The policy does not check
/// these conditions; it only chooses within them.
pub trait StatelessRetryPolicy {
    /// Whether to send a Retry for `input`.
    fn decide(&self, input: &StatelessRetryInput<'_>) -> StatelessRetryDecision;
}

impl<P: StatelessRetryPolicy + ?Sized> StatelessRetryPolicy for &P {
    fn decide(&self, input: &StatelessRetryInput<'_>) -> StatelessRetryDecision {
        (**self).decide(input)
    }
}

impl<P: StatelessRetryPolicy + ?Sized> StatelessRetryPolicy for Arc<P> {
    fn decide(&self, input: &StatelessRetryInput<'_>) -> StatelessRetryDecision {
        (**self).decide(input)
    }
}

/// What a [`StatelessRetryPolicy`] sees of an Initial packet that may get a Retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatelessRetryInput<'a> {
    /// The token the packet carries.
    pub token: PresentedToken,
    /// The address the packet came from.
    pub peer: &'a SocketAddr,
    /// How many incoming connections wait for the application to take them.
    pub waiting_incoming: usize,
    /// How many incoming connections can wait at most.
    pub incoming_capacity: NonZeroUsize,
}

/// The token an Initial packet that may get a Retry carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PresentedToken {
    /// The packet has no token.
    Absent,
    /// A NEW_TOKEN token that is authentic, not expired, and not accepted
    /// before, with how its address compares with the client's.
    NewToken(NewTokenAddress),
    /// A token that is not a valid NEW_TOKEN token; the endpoint proceeds as
    /// if the packet had none (RFC 9000 §8.1.3).
    InvalidNewToken,
}

/// What a [`StatelessRetryPolicy`] decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StatelessRetryDecision {
    /// Send a Retry and keep no state.
    SendRetry,
    /// Go on with the attempt without a Retry.
    Continue,
}

/// Sends a Retry when the queue of incoming connections is loaded: when more
/// of them wait than a fraction of the queue's capacity, an Initial packet
/// without a validated address gets a Retry.
///
/// A packet whose NEW_TOKEN token validated the client's address
/// ([`NewTokenAddress::Validated`]) never gets one. A packet with no token,
/// an invalid one, or a NEW_TOKEN token that matched only loosely
/// ([`NewTokenAddress::LooselyMatched`]) gets one under load. A connection
/// thus costs no extra round trip normally, and a flood of Initial packets
/// meets an address check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LoadStatelessRetryPolicy {
    threshold: CapacityFraction,
}

impl LoadStatelessRetryPolicy {
    /// A policy that sends a Retry when more incoming connections wait than
    /// `threshold` of the queue's capacity.
    #[must_use]
    pub fn new(threshold: CapacityFraction) -> Self {
        Self { threshold }
    }

    /// The fraction of the queue's capacity past which the policy sends a
    /// Retry.
    #[must_use]
    pub fn threshold(&self) -> CapacityFraction {
        self.threshold
    }
}

impl Default for LoadStatelessRetryPolicy {
    /// A policy that sends a Retry when more than half of the queue's
    /// capacity is waiting.
    fn default() -> Self {
        Self::new(CapacityFraction::HALF)
    }
}

impl StatelessRetryPolicy for LoadStatelessRetryPolicy {
    fn decide(&self, input: &StatelessRetryInput<'_>) -> StatelessRetryDecision {
        let validated = input.token == PresentedToken::NewToken(NewTokenAddress::Validated);
        if !validated
            && self
                .threshold
                .is_exceeded_by(input.waiting_incoming, input.incoming_capacity)
        {
            StatelessRetryDecision::SendRetry
        } else {
            StatelessRetryDecision::Continue
        }
    }
}

/// A fraction of a capacity, from zero to one inclusive.
///
/// An amount exceeds the fraction when it is greater than the fraction of
/// the capacity, so a fraction of zero is exceeded by any amount above zero
/// and a fraction of one by no amount up to the capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CapacityFraction {
    numerator: u32,
    denominator: NonZeroU32,
}

impl CapacityFraction {
    /// One half.
    pub const HALF: Self = Self {
        numerator: 1,
        denominator: NonZeroU32::new(2).unwrap(),
    };

    /// `numerator / denominator`.
    ///
    /// # Errors
    ///
    /// Fails when `numerator` is greater than `denominator`.
    pub fn new(
        numerator: u32,
        denominator: NonZeroU32,
    ) -> Result<Self, CapacityFractionAboveOneError> {
        ensure!(
            numerator <= denominator.get(),
            CapacityFractionAboveOneSnafu {
                numerator,
                denominator,
            }
        );
        Ok(Self {
            numerator,
            denominator,
        })
    }

    /// The numerator.
    #[must_use]
    pub fn numerator(&self) -> u32 {
        self.numerator
    }

    /// The denominator.
    #[must_use]
    pub fn denominator(&self) -> NonZeroU32 {
        self.denominator
    }

    /// Whether `amount` is greater than this fraction of `capacity`.
    #[must_use]
    pub fn is_exceeded_by(&self, amount: usize, capacity: NonZeroUsize) -> bool {
        // amount / capacity > numerator / denominator, without division. Each
        // product of a usize and a u32 fits in a u128.
        amount as u128 * u128::from(self.denominator.get())
            > capacity.get() as u128 * u128::from(self.numerator)
    }
}

/// A [`CapacityFraction`] would be greater than one.
#[derive(Debug, Snafu)]
#[snafu(display("capacity fraction {numerator}/{denominator} is greater than one"))]
pub struct CapacityFractionAboveOneError {
    numerator: u32,
    denominator: NonZeroU32,
}

impl CapacityFractionAboveOneError {
    /// The numerator given.
    #[must_use]
    pub fn numerator(&self) -> u32 {
        self.numerator
    }

    /// The denominator given, smaller than the numerator.
    #[must_use]
    pub fn denominator(&self) -> NonZeroU32 {
        self.denominator
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapacityFraction, LoadStatelessRetryPolicy, PresentedToken, StatelessRetryDecision,
        StatelessRetryInput, StatelessRetryPolicy,
    };
    use crate::address_token::NewTokenAddress;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        num::{NonZeroU32, NonZeroUsize},
        sync::Arc,
    };

    const PEER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);

    const NOT_VALIDATED: [PresentedToken; 3] = [
        PresentedToken::Absent,
        PresentedToken::InvalidNewToken,
        PresentedToken::NewToken(NewTokenAddress::LooselyMatched),
    ];

    fn input(
        token: PresentedToken,
        waiting: usize,
        capacity: usize,
    ) -> StatelessRetryInput<'static> {
        StatelessRetryInput {
            token,
            peer: &PEER,
            waiting_incoming: waiting,
            incoming_capacity: NonZeroUsize::new(capacity).unwrap(),
        }
    }

    fn fraction(numerator: u32, denominator: u32) -> CapacityFraction {
        CapacityFraction::new(numerator, NonZeroU32::new(denominator).unwrap()).unwrap()
    }

    #[test]
    fn the_default_sends_a_retry_past_half_the_capacity() {
        let policy = LoadStatelessRetryPolicy::default();
        assert_eq!(policy.threshold(), CapacityFraction::HALF);
        for token in NOT_VALIDATED {
            assert_eq!(
                policy.decide(&input(token, 0, 8)),
                StatelessRetryDecision::Continue
            );
            assert_eq!(
                policy.decide(&input(token, 4, 8)),
                StatelessRetryDecision::Continue
            );
            assert_eq!(
                policy.decide(&input(token, 5, 8)),
                StatelessRetryDecision::SendRetry
            );
            assert_eq!(
                policy.decide(&input(token, 8, 8)),
                StatelessRetryDecision::SendRetry
            );
            // An odd capacity: half of 7 is 3.5.
            assert_eq!(
                policy.decide(&input(token, 3, 7)),
                StatelessRetryDecision::Continue
            );
            assert_eq!(
                policy.decide(&input(token, 4, 7)),
                StatelessRetryDecision::SendRetry
            );
        }
    }

    #[test]
    fn a_validated_new_token_never_gets_a_retry() {
        let policy = LoadStatelessRetryPolicy::new(fraction(0, 1));
        let token = PresentedToken::NewToken(NewTokenAddress::Validated);
        assert_eq!(
            policy.decide(&input(token, 8, 8)),
            StatelessRetryDecision::Continue
        );
    }

    #[test]
    fn the_bounds_of_the_fraction() {
        let zero = LoadStatelessRetryPolicy::new(fraction(0, 3));
        assert_eq!(
            zero.decide(&input(PresentedToken::Absent, 0, 8)),
            StatelessRetryDecision::Continue
        );
        assert_eq!(
            zero.decide(&input(PresentedToken::Absent, 1, 8)),
            StatelessRetryDecision::SendRetry
        );
        let one = LoadStatelessRetryPolicy::new(fraction(3, 3));
        assert_eq!(
            one.decide(&input(PresentedToken::Absent, 8, 8)),
            StatelessRetryDecision::Continue
        );
        let huge = fraction(u32::MAX, u32::MAX);
        assert!(!huge.is_exceeded_by(usize::MAX, NonZeroUsize::MAX));
        assert!(fraction(0, u32::MAX).is_exceeded_by(1, NonZeroUsize::MAX));
    }

    #[test]
    fn a_fraction_above_one_is_rejected() {
        let error = CapacityFraction::new(3, NonZeroU32::new(2).unwrap()).unwrap_err();
        assert_eq!(error.numerator(), 3);
        assert_eq!(error.denominator().get(), 2);
        assert_eq!(
            error.to_string(),
            "capacity fraction 3/2 is greater than one"
        );
    }

    #[test]
    fn references_and_arcs_forward() {
        fn decide(policy: impl StatelessRetryPolicy) -> StatelessRetryDecision {
            policy.decide(&input(PresentedToken::Absent, 8, 8))
        }
        let policy = LoadStatelessRetryPolicy::default();
        let by_ref = &policy;
        assert_eq!(decide(by_ref), StatelessRetryDecision::SendRetry);
        assert_eq!(decide(Arc::new(policy)), StatelessRetryDecision::SendRetry);
    }
}
