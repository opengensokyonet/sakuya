//! Address validation and the anti-amplification limit of a logical link.
//!
//! Both are kept per logical link, in the connection's entry for it: every
//! link path over the same logical link shares them, whichever logical path
//! it belongs to.

use core::{num::NonZeroU8, task::Waker};

use snafu::{Snafu, ensure};

/// Whether the address of a logical link is validated (RFC 9000 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressValidation {
    /// Not validated: what this side sends is limited by
    /// [`AntiAmplification`].
    NotValidated,
    /// Validated, or exempt: a client's own address, or a link that arrives
    /// validated.
    Validated,
}

/// How many times the bytes received from an address not yet validated
/// may be sent to it: 1, 2 or 3, by default 3.
///
/// RFC 9000 §8 and §8.1 cap it at three; a smaller factor is only more
/// cautious. It applies during the handshake and during migration alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AntiAmplificationFactor(NonZeroU8);

impl AntiAmplificationFactor {
    /// The largest factor RFC 9000 allows, and the default.
    pub const MAX: Self = Self(NonZeroU8::new(3).unwrap());

    /// The factor `factor`.
    ///
    /// # Errors
    ///
    /// `factor` is 0 or more than 3.
    pub fn new(factor: u8) -> Result<Self, AntiAmplificationFactorError> {
        ensure!(
            (1..=Self::MAX.get()).contains(&factor),
            AntiAmplificationFactorSnafu { factor }
        );
        // invariant: checked above to be at least 1
        Ok(Self(
            NonZeroU8::new(factor).expect("checked to be at least 1"),
        ))
    }

    /// The factor as a number.
    pub fn get(self) -> u8 {
        self.0.get()
    }
}

impl Default for AntiAmplificationFactor {
    fn default() -> Self {
        Self::MAX
    }
}

/// An anti-amplification factor outside 1 to 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("anti-amplification factor {factor} is not 1, 2 or 3"))]
pub struct AntiAmplificationFactorError {
    /// The factor given.
    pub factor: u8,
}

/// The bytes this side may still send to an address not yet validated:
/// the bytes received from it times the factor, less what was sent to it.
///
/// It counts whole datagrams, before packet protection is removed: a
/// datagram whose packets are all dropped counts too (RFC 9000 §8.1). A
/// link path whose datagrams the limit holds back waits on it, and is woken
/// when the credit grows.
#[derive(Debug)]
pub struct AntiAmplification {
    factor: AntiAmplificationFactor,
    received: u64,
    sent: u64,
    waiters: Vec<Waker>,
}

impl AntiAmplification {
    /// No bytes received or sent yet.
    pub fn new(factor: AntiAmplificationFactor) -> Self {
        Self {
            factor,
            received: 0,
            sent: 0,
            waiters: Vec::new(),
        }
    }

    /// The bytes that may still be sent, or `None` when the address is
    /// validated and nothing limits them.
    pub fn credit(&self, validation: AddressValidation) -> Option<u64> {
        match validation {
            AddressValidation::Validated => None,
            AddressValidation::NotValidated => Some(
                self.received
                    .saturating_mul(u64::from(self.factor.get()))
                    .saturating_sub(self.sent),
            ),
        }
    }

    /// A datagram of `bytes` bytes arrived over the logical link: the
    /// credit grows, and what waits on it is woken.
    pub fn received(&mut self, bytes: usize) {
        self.received = self.received.saturating_add(bytes as u64);
        for waker in self.waiters.drain(..) {
            waker.wake();
        }
    }

    /// Datagrams of `bytes` bytes in all were sent over the logical link.
    pub fn sent(&mut self, bytes: usize) {
        self.sent = self.sent.saturating_add(bytes as u64);
    }

    /// Wake `waker` when the credit next grows.
    pub fn wait(&mut self, waker: &Waker) {
        if !self.waiters.iter().any(|w| w.will_wake(waker)) {
            self.waiters.push(waker.clone());
        }
    }
}
