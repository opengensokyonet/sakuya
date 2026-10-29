//! Detecting a received stateless reset before ordinary routing
//!
//! Every datagram is checked for a stateless reset from the peer
//! ([RFC 9000 §10.3]) before it is classified. The check uses the last 16
//! bytes of the whole datagram, not of its first packet; a datagram shorter
//! than that is never a hit. A hit ends ordinary routing: no candidates are
//! built, and the datagram is released. Detection is not a deliverer that
//! competes for every datagram.
//!
//! This concerns resets this side **receives**, matched against tokens the
//! peer provided; it is unrelated to sending a reset for unknown input, and to
//! an ordinary candidate failing its judgment.
//!
//! [RFC 9000 §10.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3

use std::convert::Infallible;
use std::fmt;
use std::sync::{Arc, Weak};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry as MapEntry;
use sakuya_link::LinkId;
use sakuya_wire::connection_id::StatelessResetToken;
use smallvec::SmallVec;

/// The capability that handles a received stateless reset for its target.
pub trait StatelessResetTarget {
    /// Handles a valid stateless reset received for this target.
    ///
    /// Routing calls it after detection returned, outside every lock of the
    /// detector and the index. The target may already be terminated; then it
    /// need not do anything.
    fn stateless_reset_received(&self);
}

impl StatelessResetTarget for Infallible {
    fn stateless_reset_received(&self) {
        match *self {}
    }
}

impl<Target: StatelessResetTarget + ?Sized> StatelessResetTarget for Arc<Target> {
    fn stateless_reset_received(&self) {
        (**self).stateless_reset_received();
    }
}

/// Recognizes a received stateless reset and names the target it resets.
pub trait StatelessResetDetector {
    /// What a hit resets.
    type Target: StatelessResetTarget;

    /// Checks `tail`, the last [`StatelessResetToken::LEN`] bytes of a
    /// datagram that arrived on `link`, read as a token.
    ///
    /// A hit must carry the target it belongs to, so that the caller never
    /// guesses it again. It must not run the target itself.
    fn detect(&self, tail: &StatelessResetToken, link: &LinkId) -> Option<Self::Target>;
}

/// No detection: no datagram is a stateless reset.
impl StatelessResetDetector for () {
    type Target = Infallible;

    fn detect(&self, _tail: &StatelessResetToken, _link: &LinkId) -> Option<Infallible> {
        None
    }
}

/// A detector over the tokens the connection side registered.
///
/// Connection ID and token management registers each token that currently
/// applies, with the target to reset, and drops the registration when the
/// token stops applying. A hit returns a reference to the target registered
/// first under the token; no target code runs while the token table is
/// locked.
pub struct StatelessResetTokens<Target> {
    tokens: DashMap<StatelessResetToken, SmallVec<[Arc<Target>; 1]>>,
}

impl<Target> StatelessResetTokens<Target> {
    /// Creates a detector without tokens.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tokens: DashMap::new(),
        })
    }

    /// Registers `token` for `target` until the registration is dropped.
    pub fn register(
        self: &Arc<Self>,
        token: StatelessResetToken,
        target: Target,
    ) -> StatelessResetRegistration<Target> {
        let target = Arc::new(target);
        self.tokens
            .entry(token)
            .or_default()
            .push(Arc::clone(&target));
        StatelessResetRegistration {
            detector: Arc::downgrade(self),
            token,
            target,
        }
    }

    fn remove(&self, token: &StatelessResetToken, target: &Arc<Target>) -> Option<Arc<Target>> {
        let MapEntry::Occupied(mut slot) = self.tokens.entry(*token) else {
            return None;
        };
        let position = slot
            .get()
            .iter()
            .position(|current| Arc::ptr_eq(current, target))?;
        let removed = slot.get_mut().remove(position);
        if slot.get().is_empty() {
            drop(slot.remove());
        }
        Some(removed)
    }
}

impl<Target: StatelessResetTarget> StatelessResetDetector for StatelessResetTokens<Target> {
    type Target = Arc<Target>;

    fn detect(&self, tail: &StatelessResetToken, _link: &LinkId) -> Option<Arc<Target>> {
        self.tokens.get(tail)?.first().cloned()
    }
}

impl<Detector: StatelessResetDetector + ?Sized> StatelessResetDetector for Arc<Detector> {
    type Target = Detector::Target;

    fn detect(&self, tail: &StatelessResetToken, link: &LinkId) -> Option<Self::Target> {
        (**self).detect(tail, link)
    }
}

impl<Target> fmt::Debug for StatelessResetTokens<Target> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatelessResetTokens")
            .field("tokens", &self.tokens.len())
            .finish()
    }
}

/// Keeps one stateless reset token registered; dropping it revokes exactly
/// that registration.
#[must_use = "dropping the registration revokes the token"]
pub struct StatelessResetRegistration<Target> {
    detector: Weak<StatelessResetTokens<Target>>,
    token: StatelessResetToken,
    target: Arc<Target>,
}

impl<Target> Drop for StatelessResetRegistration<Target> {
    fn drop(&mut self) {
        if let Some(detector) = self.detector.upgrade() {
            drop(detector.remove(&self.token, &self.target));
        }
    }
}

impl<Target> fmt::Debug for StatelessResetRegistration<Target> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatelessResetRegistration")
            .finish_non_exhaustive()
    }
}
