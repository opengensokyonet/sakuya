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
use std::hash::Hash;
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
///
/// `Local` and `Peer` are the ends of the links the datagrams arrive on
/// ([`sakuya_link::Link::Local`], [`sakuya_link::Link::Peer`]).
pub trait StatelessResetDetector<Local, Peer> {
    /// What a hit resets.
    type Target: StatelessResetTarget;

    /// Checks `tail`, the last [`StatelessResetToken::LEN`] bytes of a
    /// datagram that arrived on `link`, read as a token.
    ///
    /// A hit must carry the target it belongs to, so that the caller never
    /// guesses it again. It must not run the target itself.
    fn detect(
        &self,
        tail: &StatelessResetToken,
        link: &LinkId<Local, Peer>,
    ) -> Option<Self::Target>;
}

/// No detection: no datagram is a stateless reset.
impl<Local, Peer> StatelessResetDetector<Local, Peer> for () {
    type Target = Infallible;

    fn detect(
        &self,
        _tail: &StatelessResetToken,
        _link: &LinkId<Local, Peer>,
    ) -> Option<Infallible> {
        None
    }
}

/// A detector over the tokens the connection side registered, grouped by the
/// peer they apply to.
///
/// RFC 9000 §10.3.1 compares the trailing bytes of a datagram only with the
/// tokens associated with the remote end it came from. Connection ID
/// management registers a token for a peer when the connection ID it belongs
/// to is first sent to that peer, and drops the registration when the
/// connection ID is retired or the link path to that peer is removed,
/// whichever comes first.
///
/// Detection looks up the group of the arriving link's
/// [`peer`](LinkId::peer) and compares the tail with each token in the group
/// in constant time ([`StatelessResetToken`]'s equality), stopping at the
/// first match. The time a lookup takes depends on the peer and on the number
/// of tokens in its group, never on a token's value. A hit returns a
/// reference to the target registered first under that token for that peer;
/// no target code runs while the token table is locked.
pub struct StatelessResetTokens<Peer, Target> {
    by_peer: DashMap<Peer, PeerTokens<Target>>,
}

/// The tokens registered for one peer, each with its target, in the order
/// they were registered.
type PeerTokens<Target> = SmallVec<[(StatelessResetToken, Arc<Target>); 2]>;

impl<Peer: Clone + Eq + Hash, Target> StatelessResetTokens<Peer, Target> {
    /// Creates a detector without tokens.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            by_peer: DashMap::new(),
        })
    }

    /// Registers `token` for `target` on datagrams from `peer` until the
    /// registration is dropped.
    pub fn register(
        self: &Arc<Self>,
        peer: Peer,
        token: StatelessResetToken,
        target: Target,
    ) -> StatelessResetRegistration<Peer, Target> {
        let target = Arc::new(target);
        self.by_peer
            .entry(peer.clone())
            .or_default()
            .push((token, Arc::clone(&target)));
        StatelessResetRegistration {
            detector: Arc::downgrade(self),
            peer,
            target,
        }
    }

    fn remove(&self, peer: &Peer, target: &Arc<Target>) -> Option<Arc<Target>> {
        let MapEntry::Occupied(mut slot) = self.by_peer.entry(peer.clone()) else {
            return None;
        };
        let position = slot
            .get()
            .iter()
            .position(|(_, current)| Arc::ptr_eq(current, target))?;
        let (_, removed) = slot.get_mut().remove(position);
        if slot.get().is_empty() {
            drop(slot.remove());
        }
        Some(removed)
    }
}

impl<Local, Peer: Eq + Hash, Target: StatelessResetTarget> StatelessResetDetector<Local, Peer>
    for StatelessResetTokens<Peer, Target>
{
    type Target = Arc<Target>;

    fn detect(
        &self,
        tail: &StatelessResetToken,
        link: &LinkId<Local, Peer>,
    ) -> Option<Arc<Target>> {
        let group = self.by_peer.get(&link.peer)?;
        group
            .iter()
            .find(|(token, _)| token == tail)
            .map(|(_, target)| Arc::clone(target))
    }
}

impl<Local, Peer, Detector: StatelessResetDetector<Local, Peer> + ?Sized>
    StatelessResetDetector<Local, Peer> for Arc<Detector>
{
    type Target = Detector::Target;

    fn detect(
        &self,
        tail: &StatelessResetToken,
        link: &LinkId<Local, Peer>,
    ) -> Option<Self::Target> {
        (**self).detect(tail, link)
    }
}

impl<Peer: Eq + Hash, Target> fmt::Debug for StatelessResetTokens<Peer, Target> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatelessResetTokens")
            .field("peers", &self.by_peer.len())
            .finish()
    }
}

/// Keeps one stateless reset token registered for one peer; dropping it
/// revokes exactly that registration.
#[must_use = "dropping the registration revokes the token"]
pub struct StatelessResetRegistration<Peer: Clone + Eq + Hash, Target> {
    detector: Weak<StatelessResetTokens<Peer, Target>>,
    peer: Peer,
    target: Arc<Target>,
}

impl<Peer: Clone + Eq + Hash, Target> Drop for StatelessResetRegistration<Peer, Target> {
    fn drop(&mut self) {
        if let Some(detector) = self.detector.upgrade() {
            drop(detector.remove(&self.peer, &self.target));
        }
    }
}

impl<Peer: Clone + Eq + Hash, Target> fmt::Debug for StatelessResetRegistration<Peer, Target> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatelessResetRegistration")
            .finish_non_exhaustive()
    }
}
