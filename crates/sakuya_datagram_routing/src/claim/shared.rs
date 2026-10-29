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
use std::mem;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError};

use super::finish::UnclaimedHandoff;

/// The finish policy of one datagram.
///
/// The two policies are exclusive; see the [module
/// documentation](super#finish-policies).
pub enum DatagramFinishPolicy<Handoff> {
    /// A sole remaining participant may take the datagram directly; when all
    /// participants exit, the datagram is released.
    LastTakes,
    /// Every participant must judge; when all exit while the datagram is
    /// present, the last exit hands it to the handoff, once.
    OnUnclaimed(Handoff),
}

/// Whether the original datagram is still in the shared slot.
pub(super) enum DatagramSlot<Inner> {
    /// No candidate took the datagram yet.
    Present(Inner),
    /// A candidate took the datagram; it is never put back.
    Taken,
}

/// The private core shared by the candidates of one datagram.
pub(super) struct ClaimCore<Inner, Handoff: UnclaimedHandoff<Inner>> {
    pub(super) input: tokio::sync::Mutex<DatagramSlot<Inner>>,
    participants: AtomicUsize,
    committed: AtomicBool,
    /// The handoff is only touched through `&mut self` in `Drop`; the mutex
    /// makes the core `Sync` without requiring the handoff to be `Sync`.
    finish: DatagramFinishPolicy<std::sync::Mutex<Handoff>>,
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>> ClaimCore<Inner, Handoff> {
    /// Creates an uncommitted core without participants.
    pub(super) fn new(datagram: Inner, finish: DatagramFinishPolicy<Handoff>) -> Arc<Self> {
        let finish = match finish {
            DatagramFinishPolicy::LastTakes => DatagramFinishPolicy::LastTakes,
            DatagramFinishPolicy::OnUnclaimed(handoff) => {
                DatagramFinishPolicy::OnUnclaimed(std::sync::Mutex::new(handoff))
            }
        };
        Arc::new(Self {
            input: tokio::sync::Mutex::new(DatagramSlot::Present(datagram)),
            participants: AtomicUsize::new(0),
            committed: AtomicBool::new(false),
            finish,
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
        matches!(self.finish, DatagramFinishPolicy::LastTakes)
            && self.participants.load(Ordering::Acquire) == 1
    }

    #[cfg(test)]
    pub(super) fn participants(&self) -> usize {
        self.participants.load(Ordering::Acquire)
    }
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>> Drop for ClaimCore<Inner, Handoff> {
    fn drop(&mut self) {
        debug_assert_eq!(*self.participants.get_mut(), 0);
        let slot = mem::replace(self.input.get_mut(), DatagramSlot::Taken);
        let finish = mem::replace(&mut self.finish, DatagramFinishPolicy::LastTakes);
        if *self.committed.get_mut()
            && let (DatagramSlot::Present(datagram), DatagramFinishPolicy::OnUnclaimed(handoff)) =
                (slot, finish)
        {
            // The mutex is never locked, so it cannot be poisoned.
            let handoff = handoff.into_inner().unwrap_or_else(PoisonError::into_inner);
            handoff.hand_off(datagram);
        }
    }
}

/// One candidate's participation credential.
///
/// It cannot be cloned; it is created only while the candidate set is being
/// prepared, and it holds the only kind of strong reference to the core.
pub struct Participation<Inner, Handoff: UnclaimedHandoff<Inner>> {
    core: Arc<ClaimCore<Inner, Handoff>>,
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>> Participation<Inner, Handoff> {
    /// Adds one participant to a core that is still being prepared.
    pub(super) fn join(core: &Arc<ClaimCore<Inner, Handoff>>) -> Self {
        // The set is not yet published; publication orders this increment
        // before any participant reads the count.
        core.participants.fetch_add(1, Ordering::Relaxed);
        Self {
            core: Arc::clone(core),
        }
    }

    pub(super) fn core(&self) -> &ClaimCore<Inner, Handoff> {
        &self.core
    }

    #[cfg(test)]
    pub(super) fn core_handle(&self) -> Arc<ClaimCore<Inner, Handoff>> {
        Arc::clone(&self.core)
    }
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>> Drop for Participation<Inner, Handoff> {
    fn drop(&mut self) {
        self.core.participants.fetch_sub(1, Ordering::AcqRel);
        // The strong reference is released after the count, when the field
        // drops; the last one runs `ClaimCore::drop`.
    }
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>> fmt::Debug for Participation<Inner, Handoff> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Participation").finish_non_exhaustive()
    }
}
