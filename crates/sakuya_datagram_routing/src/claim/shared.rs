//! The core shared by the candidates of one datagram
//!
//! The core holds the single original datagram behind the asynchronous access
//! lock, the atomic participation count, the finish policy and whether the
//! candidate set was committed. Its strong references belong only to
//! participation credentials: the preparer's own reference is released when
//! the set is committed, no observer or winner keeps the core alive, and no
//! owned lock guard or weak reference to it leaves the mechanism. Releasing the
//! last credential therefore drops the core, and [`Drop`] gets exclusive access
//! to the datagram slot through `&mut self` without locking.
//!
//! The participation count is the source of truth for uniqueness. It always
//! equals the number of live credentials, which with the layout above is also
//! the number of strong references once the set is committed; the mechanism
//! never reads the reference count.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError};

/// The capability that takes over a datagram nobody claimed.
///
/// It is called synchronously by the last exit, which may be anywhere
/// downstream: in a connection loop, a cancelled future or a dropped delivery.
/// It must only move the datagram, with whatever routing context it captured,
/// to an outside capability; the next lookup, preparation or delivery must not
/// run on the current call stack. A closure type cannot prove this; it is the
/// provider's contract.
pub(crate) type UnclaimedHandoff<Inner> = Box<dyn FnOnce(Inner) + Send>;

/// The finish policy of one datagram.
///
/// The two policies are exclusive; see the [module
/// documentation](super#finish-policies).
pub enum DatagramFinishPolicy<Inner> {
    /// A sole remaining participant may take the datagram directly; when all
    /// participants exit, the datagram is released.
    LastTakes,
    /// Every participant must judge; when all exit while the datagram is
    /// present, the last exit hands it to the capability, once.
    OnUnclaimed(UnclaimedHandoff<Inner>),
}

/// The private core shared by the candidates of one datagram.
pub(super) struct ClaimCore<Inner> {
    /// The single original datagram; `None` once a candidate took it.
    pub(super) input: tokio::sync::Mutex<Option<Inner>>,
    participants: AtomicUsize,
    last_takes: bool,
    committed: AtomicBool,
    /// Only touched through `&mut self` in `Drop`; the mutex makes the core
    /// `Sync` without requiring the handoff to be `Sync`.
    handoff: std::sync::Mutex<Option<UnclaimedHandoff<Inner>>>,
}

impl<Inner> ClaimCore<Inner> {
    /// Creates an uncommitted core without participants.
    pub(super) fn new(datagram: Inner, finish: DatagramFinishPolicy<Inner>) -> Arc<Self> {
        let (last_takes, handoff) = match finish {
            DatagramFinishPolicy::LastTakes => (true, None),
            DatagramFinishPolicy::OnUnclaimed(handoff) => (false, Some(handoff)),
        };
        Arc::new(Self {
            input: tokio::sync::Mutex::new(Some(datagram)),
            participants: AtomicUsize::new(0),
            last_takes,
            committed: AtomicBool::new(false),
            handoff: std::sync::Mutex::new(handoff),
        })
    }

    /// Marks the candidate set complete, just before the first delivery.
    ///
    /// Before this point, dropping every credential only releases the
    /// datagram; after it, the on-unclaimed handoff applies.
    pub(super) fn commit(&self) {
        // Publication of the candidates to other threads, and the final
        // reference count decrement, order this store before `Drop` reads it.
        self.committed.store(true, Ordering::Relaxed);
    }

    /// Whether a sole remaining participant may take the datagram directly.
    ///
    /// Called while holding the access, by a participant whose credential is
    /// alive. The set is complete once committed, so reading one means no
    /// other participant can appear.
    pub(super) fn sole_participant_takes(&self) -> bool {
        self.last_takes && self.participants.load(Ordering::Acquire) == 1
    }

    #[cfg(test)]
    pub(super) fn participants(&self) -> usize {
        self.participants.load(Ordering::Acquire)
    }
}

impl<Inner> Drop for ClaimCore<Inner> {
    fn drop(&mut self) {
        debug_assert_eq!(*self.participants.get_mut(), 0);
        let datagram = self.input.get_mut().take();
        let handoff = self
            .handoff
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if *self.committed.get_mut()
            && let (Some(datagram), Some(handoff)) = (datagram, handoff)
        {
            handoff(datagram);
        }
    }
}

/// One candidate's participation credential.
///
/// It cannot be cloned; it is created only while the candidate set is being
/// prepared, and it holds the only kind of strong reference to the core.
pub struct Participation<Inner> {
    core: Arc<ClaimCore<Inner>>,
}

impl<Inner> Participation<Inner> {
    /// Adds one participant to a core that is still being prepared.
    pub(super) fn join(core: &Arc<ClaimCore<Inner>>) -> Self {
        // The set is not yet published; publication orders this increment
        // before any participant reads the count.
        core.participants.fetch_add(1, Ordering::Relaxed);
        Self {
            core: Arc::clone(core),
        }
    }

    pub(super) fn core(&self) -> &ClaimCore<Inner> {
        &self.core
    }

    #[cfg(test)]
    pub(super) fn core_handle(&self) -> Arc<ClaimCore<Inner>> {
        Arc::clone(&self.core)
    }
}

impl<Inner> Drop for Participation<Inner> {
    fn drop(&mut self) {
        self.core.participants.fetch_sub(1, Ordering::AcqRel);
        // The strong reference is released after the count, when the field
        // drops; the last one runs `ClaimCore::drop`.
    }
}

impl<Inner> fmt::Debug for Participation<Inner> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Participation").finish_non_exhaustive()
    }
}
