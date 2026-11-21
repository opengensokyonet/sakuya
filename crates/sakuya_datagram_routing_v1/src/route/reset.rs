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

use alloc::rc::{Rc, Weak};
use alloc::sync::Arc;
use core::cell::RefCell;
use core::convert::Infallible;
use core::fmt;
use core::hash::{BuildHasher, Hash};

use hashbrown::{HashMap, hash_map::Entry as MapEntry};
use sakuya_link::LinkId;
use sakuya_wire_v1::connection_id::StatelessResetToken;
use smallvec::SmallVec;

/// The capability that handles a received stateless reset for its target.
pub trait StatelessResetTarget {
    /// Handles a valid stateless reset received for this target.
    ///
    /// Routing calls it after detection returned, outside every access of
    /// the detector and the index. The target may already be terminated; then it
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

/// The tokens the connection side registered, grouped by the peer they apply
/// to (`StatelessResetTokens`): a handle, whose clones are the same table.
///
/// RFC 9000 §10.3.1 compares the trailing bytes of a datagram only with the
/// tokens associated with the remote end it came from. Connection ID
/// management registers a token for a peer when the connection ID it belongs
/// to is first sent to that peer, and drops the registration when the
/// connection ID is retired or the link path to that peer is removed,
/// whichever comes first.
///
/// Detection ([`detect_from`](Self::detect_from)) looks up the group of the
/// arriving link's peer and compares the tail with each token in the group in
/// constant time ([`StatelessResetToken`]'s equality), stopping at the first
/// match. The time a lookup takes depends on the peer and on the number of
/// tokens in its group, never on a token's value. A hit returns a reference
/// to the target registered first under that token for that peer; no target
/// code runs within an access of the table.
///
/// An implementation stores the groups, one per peer, and gives the entry
/// accesses below, under the same contract as the
/// [route index](super::index::RouteIndex): every read and every update of
/// one peer's group runs within one access to it, and an update never
/// interleaves with another access to the same group. An update starts from
/// an empty group when the peer has none, and a group an update leaves empty
/// is removed. Registering, revoking and detecting are this crate's, on top
/// of the accesses. The table is `Send` and `Sync` exactly as its
/// implementation makes it; a router detects with it through an
/// implementation of [`StatelessResetDetector`].
pub trait StatelessResetTokens<Peer, Target>: Clone {
    /// Keeps one token registered for one peer; dropping it revokes exactly
    /// that registration, through [`revoke`](StatelessResetTokens::revoke),
    /// unless the table is gone (`StatelessResetRegistration`). How it finds
    /// the table again is the implementation's.
    type Registration;

    /// Creates a table without tokens.
    fn new() -> Self;

    /// Runs `read` within one access to the group of `peer`, if it has one.
    fn read<R>(
        &self,
        peer: &Peer,
        read: impl FnOnce(&PeerStatelessResetTokens<Target>) -> R,
    ) -> Option<R>;

    /// Runs `update` within one access to the group of `peer`, which starts
    /// empty when there is none and is removed when `update` leaves it
    /// empty.
    fn update<R>(
        &self,
        peer: &Peer,
        update: impl FnOnce(&mut PeerStatelessResetTokens<Target>) -> R,
    ) -> R;

    /// The registration of `target` for `peer`, which this crate has just
    /// registered: the handle that revokes it.
    fn hold(&self, peer: Peer, target: Arc<Target>) -> Self::Registration;

    /// Registers `token` for `target` on datagrams from `peer` until the
    /// registration is dropped.
    fn register(
        &self,
        peer: Peer,
        token: StatelessResetToken,
        target: Target,
    ) -> Self::Registration {
        let target = Arc::new(target);
        let registered = Arc::clone(&target);
        self.update(&peer, |group| group.tokens.push((token, registered)));
        self.hold(peer, target)
    }

    /// Revokes exactly the registration of `target` for `peer`, if it is
    /// still registered. The registration calls it when dropped.
    ///
    /// The table's reference to the target is dropped outside the access.
    fn revoke(&self, peer: &Peer, target: &Arc<Target>) {
        let removed = self.update(peer, |group| {
            let position = group
                .tokens
                .iter()
                .position(|(_, current)| Arc::ptr_eq(current, target))?;
            Some(group.tokens.remove(position).1)
        });
        drop(removed);
    }

    /// The target registered first under `tail` for datagrams from `peer`,
    /// if any.
    fn detect_from(&self, tail: &StatelessResetToken, peer: &Peer) -> Option<Arc<Target>> {
        self.read(peer, |group| {
            group
                .tokens
                .iter()
                .find(|(token, _)| token == tail)
                .map(|(_, target)| Arc::clone(target))
        })
        .flatten()
    }
}

/// The tokens registered for one peer, each with its target, in the order
/// they were registered (`PeerStatelessResetTokens`).
///
/// A table keeps one per peer that has a token; only this crate reads or
/// changes what is in it.
pub struct PeerStatelessResetTokens<Target> {
    tokens: SmallVec<[(StatelessResetToken, Arc<Target>); 2]>,
}

impl<Target> PeerStatelessResetTokens<Target> {
    /// A group without tokens.
    pub fn new() -> Self {
        Self {
            tokens: SmallVec::new(),
        }
    }

    /// Whether the group has no token; a table removes such a group.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl<Target> Default for PeerStatelessResetTokens<Target> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Target> fmt::Debug for PeerStatelessResetTokens<Target> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerStatelessResetTokens")
            .field("tokens", &self.tokens.len())
            .finish()
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

/// The token table of a routing domain on one thread
/// (`HashMapStatelessResetTokens`): the groups in a hash map in a cell, which
/// the table's clones share through an `Rc`.
///
/// It is neither `Send` nor `Sync`. The keys of its map are the peers' ends
/// of the links, which the peer chooses; `S` builds their hashers, and the
/// host chooses it. A host whose endpoint an attacker can reach chooses one
/// that is seeded at random and resists the collisions an attacker crafts.
pub struct HashMapStatelessResetTokens<Peer, Target, S> {
    by_peer: Rc<RefCell<HashMap<Peer, PeerStatelessResetTokens<Target>, S>>>,
}

impl<Peer, Target, S> Clone for HashMapStatelessResetTokens<Peer, Target, S> {
    fn clone(&self) -> Self {
        Self {
            by_peer: Rc::clone(&self.by_peer),
        }
    }
}

impl<Peer, Target, S> StatelessResetTokens<Peer, Target>
    for HashMapStatelessResetTokens<Peer, Target, S>
where
    Peer: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    type Registration = HashMapStatelessResetRegistration<Peer, Target, S>;

    fn new() -> Self {
        Self {
            by_peer: Rc::new(RefCell::new(HashMap::with_hasher(S::default()))),
        }
    }

    fn read<R>(
        &self,
        peer: &Peer,
        read: impl FnOnce(&PeerStatelessResetTokens<Target>) -> R,
    ) -> Option<R> {
        self.by_peer.borrow().get(peer).map(read)
    }

    fn update<R>(
        &self,
        peer: &Peer,
        update: impl FnOnce(&mut PeerStatelessResetTokens<Target>) -> R,
    ) -> R {
        let mut by_peer = self.by_peer.borrow_mut();
        match by_peer.entry(peer.clone()) {
            MapEntry::Occupied(mut slot) => {
                let updated = update(slot.get_mut());
                if slot.get().is_empty() {
                    drop(slot.remove());
                }
                updated
            }
            MapEntry::Vacant(slot) => {
                let mut group = PeerStatelessResetTokens::new();
                let updated = update(&mut group);
                if !group.is_empty() {
                    slot.insert(group);
                }
                updated
            }
        }
    }

    fn hold(
        &self,
        peer: Peer,
        target: Arc<Target>,
    ) -> HashMapStatelessResetRegistration<Peer, Target, S> {
        HashMapStatelessResetRegistration {
            tokens: Rc::downgrade(&self.by_peer),
            peer,
            target,
        }
    }
}

impl<Local, Peer, Target, S> StatelessResetDetector<Local, Peer>
    for HashMapStatelessResetTokens<Peer, Target, S>
where
    Peer: Clone + Eq + Hash,
    Target: StatelessResetTarget,
    S: BuildHasher + Default,
{
    type Target = Arc<Target>;

    fn detect(
        &self,
        tail: &StatelessResetToken,
        link: &LinkId<Local, Peer>,
    ) -> Option<Arc<Target>> {
        self.detect_from(tail, &link.peer)
    }
}

impl<Peer, Target, S> fmt::Debug for HashMapStatelessResetTokens<Peer, Target, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashMapStatelessResetTokens")
            .field("peers", &self.by_peer.borrow().len())
            .finish()
    }
}

/// The registration of a token in a [`HashMapStatelessResetTokens`]: it
/// finds the table again through a weak reference, and revoking after the
/// table is gone does nothing.
#[must_use = "dropping the registration revokes the token"]
pub struct HashMapStatelessResetRegistration<Peer, Target, S>
where
    Peer: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    tokens: Weak<RefCell<HashMap<Peer, PeerStatelessResetTokens<Target>, S>>>,
    peer: Peer,
    target: Arc<Target>,
}

impl<Peer, Target, S> Drop for HashMapStatelessResetRegistration<Peer, Target, S>
where
    Peer: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    fn drop(&mut self) {
        if let Some(by_peer) = self.tokens.upgrade() {
            HashMapStatelessResetTokens { by_peer }.revoke(&self.peer, &self.target);
        }
    }
}

impl<Peer, Target, S> fmt::Debug for HashMapStatelessResetRegistration<Peer, Target, S>
where
    Peer: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashMapStatelessResetRegistration")
            .finish_non_exhaustive()
    }
}
