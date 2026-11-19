//! The core shared by the candidates of one datagram
//!
//! The core holds the single original datagram and the finish policy behind
//! the asynchronous access lock of the routing domain
//! ([`DatagramClaimLock`]), the atomic participation count and whether the
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

use core::fmt;
use core::mem;

#[cfg(not(sakuya_loom))]
use alloc::sync::Arc;
#[cfg(not(sakuya_loom))]
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
// Under `cfg(sakuya_loom)` the core's reference count and atomics are
// loom's, so that a loom model explores their interleavings and memory
// orderings; nothing else changes.
#[cfg(sakuya_loom)]
use loom::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use super::finish::UnclaimedHandoff;
use super::lock::DatagramClaimLock;

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

/// What the access lock of a core holds: the datagram's slot and the
/// finish policy.
///
/// The handoff of the policy is only taken through `&mut self` in `Drop`;
/// keeping it under the lock makes the core `Sync` without requiring the
/// handoff to be `Sync`.
pub(super) struct ClaimInput<Inner, Handoff> {
    pub(super) slot: DatagramSlot<Inner>,
    pub(super) finish: DatagramFinishPolicy<Handoff>,
}

impl<Inner, Handoff> ClaimInput<Inner, Handoff> {
    /// Whether the finish policy lets a sole remaining participant take the
    /// datagram directly.
    pub(super) fn last_takes(&self) -> bool {
        matches!(self.finish, DatagramFinishPolicy::LastTakes)
    }
}

/// The reference count a [`ClaimCore`] is shared by.
pub(super) type CoreArc<T> = Arc<T>;

/// The private core shared by the candidates of one datagram.
pub(super) struct ClaimCore<Inner, Handoff: UnclaimedHandoff<Inner>, Lock: DatagramClaimLock> {
    pub(super) input: Lock::Lock<ClaimInput<Inner, Handoff>>,
    participants: AtomicUsize,
    committed: AtomicBool,
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>, Lock: DatagramClaimLock>
    ClaimCore<Inner, Handoff, Lock>
{
    /// Creates an uncommitted core without participants.
    pub(super) fn new(datagram: Inner, finish: DatagramFinishPolicy<Handoff>) -> Arc<Self> {
        Arc::new(Self {
            input: Lock::new(ClaimInput {
                slot: DatagramSlot::Present(datagram),
                finish,
            }),
            participants: AtomicUsize::new(0),
            committed: AtomicBool::new(false),
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
    pub(super) fn sole_participant_takes(&self, input: &ClaimInput<Inner, Handoff>) -> bool {
        input.last_takes() && self.participants.load(Ordering::Acquire) == 1
    }

    #[cfg(test)]
    pub(super) fn participants(&self) -> usize {
        self.participants.load(Ordering::Acquire)
    }
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>, Lock: DatagramClaimLock> Drop
    for ClaimCore<Inner, Handoff, Lock>
{
    fn drop(&mut self) {
        #[cfg(not(sakuya_loom))]
        let (participants, committed) = (*self.participants.get_mut(), *self.committed.get_mut());
        // loom's atomics give no `get_mut`; with `&mut self` no other access
        // can race these reads.
        #[cfg(sakuya_loom)]
        let (participants, committed) = (
            self.participants.with_mut(|count| *count),
            self.committed.load(Ordering::Relaxed),
        );
        debug_assert_eq!(participants, 0);
        let input = Lock::get_mut(&mut self.input);
        let slot = mem::replace(&mut input.slot, DatagramSlot::Taken);
        let finish = mem::replace(&mut input.finish, DatagramFinishPolicy::LastTakes);
        if committed
            && let (DatagramSlot::Present(datagram), DatagramFinishPolicy::OnUnclaimed(handoff)) =
                (slot, finish)
        {
            handoff.hand_off(datagram);
        }
    }
}

/// One candidate's participation credential.
///
/// It cannot be cloned; it is created only while the candidate set is being
/// prepared, and it holds the only kind of strong reference to the core.
pub struct Participation<Inner, Handoff: UnclaimedHandoff<Inner>, Lock: DatagramClaimLock> {
    core: Arc<ClaimCore<Inner, Handoff, Lock>>,
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>, Lock: DatagramClaimLock>
    Participation<Inner, Handoff, Lock>
{
    /// Adds one participant to a core that is still being prepared.
    pub(super) fn join(core: &Arc<ClaimCore<Inner, Handoff, Lock>>) -> Self {
        // The set is not yet published; publication orders this increment
        // before any participant reads the count.
        core.participants.fetch_add(1, Ordering::Relaxed);
        Self {
            core: Arc::clone(core),
        }
    }

    pub(super) fn core(&self) -> &ClaimCore<Inner, Handoff, Lock> {
        &self.core
    }

    #[cfg(test)]
    pub(super) fn core_handle(&self) -> Arc<ClaimCore<Inner, Handoff, Lock>> {
        Arc::clone(&self.core)
    }
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>, Lock: DatagramClaimLock> Drop
    for Participation<Inner, Handoff, Lock>
{
    fn drop(&mut self) {
        self.core.participants.fetch_sub(1, Ordering::AcqRel);
        // The strong reference is released after the count, when the field
        // drops; the last one runs `ClaimCore::drop`.
    }
}

impl<Inner, Handoff: UnclaimedHandoff<Inner>, Lock: DatagramClaimLock> fmt::Debug
    for Participation<Inner, Handoff, Lock>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Participation").finish_non_exhaustive()
    }
}
