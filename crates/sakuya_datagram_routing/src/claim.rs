//! Claim delivery: how the candidates of one datagram compete for it
//!
//! Routing a received datagram yields a frozen set of route entries. For each
//! entry the mechanism builds one [`DatagramClaimCandidate`] and hands it to the
//! entry's [`DatagramDeliverer`] through [`DatagramDeliverer::deliver`]. All
//! candidates of one datagram share a private core that holds the single
//! original datagram and counts the candidates still participating. The
//! mechanism owns the candidate shell, the storage of the deliverer's private
//! state, access to the shared datagram and every ownership transfer; the
//! author of a deliverer only defines the content of the private state and three
//! synchronous capabilities:
//!
//! - [`new_datagram_state`](DatagramDeliverer::new_datagram_state) builds the
//!   initial private state from a read-only [`DatagramView`];
//! - [`try_claim`](DatagramDeliverer::try_claim) decides, within one
//!   synchronous access, whether to take the datagram through
//!   [`DatagramClaimAccess::into_exclusive`];
//! - [`deliver`](DatagramDeliverer::deliver) consumes a [`DatagramDelivery`]
//!   and returns unit.
//!
//! None of them waits. Waiting for business conditions, such as keys or
//! configuration, belongs to whoever holds the candidate.
//!
//! # One attempt
//!
//! [`DatagramClaimCandidate::try_exclusive`] moves the candidate into a lazy
//! future. On first poll the future waits for the shared access
//! (`tokio::sync::Mutex<Option<Inner>>`), then, in one synchronous section
//! without awaiting:
//!
//! 1. if the datagram is already gone, it yields
//!    [`DatagramClaimAttempt::ClaimedElsewhere`] without calling the factory;
//! 2. if the candidate's private state is not initialized yet, it calls the
//!    factory once with a read-only view of the datagram;
//! 3. if the datagram uses the [last-takes](#finish-policies) finish policy and
//!    this candidate is the only remaining participant, it takes the datagram
//!    directly without calling `try_claim`;
//! 4. otherwise it calls the deliverer's `try_claim`. An unclaimed outcome stores
//!    the updated state back into the same candidate.
//!
//! The access is released before the attempt completes. Dropping the future
//! before its first poll leaves the candidate without any author call; dropping
//! it while it waits first withdraws the wait, which passes the access on to
//! the next waiter, and then exits the candidate. Pausing means keeping the same
//! pinned future. [`DatagramClaimCandidate::try_exclusive_now`] performs the
//! same synchronous section only if the access is immediately available.
//!
//! # Factory calls
//!
//! The private state is created when it is first needed, so that a candidate
//! that is never consumed never runs the factory:
//!
//! | Path | Factory call |
//! | --- | --- |
//! | Creating, delivering, storing, matching or dropping an unconsumed object | none |
//! | Constructing, not polling, waiting, being woken, cancelling while waiting | none |
//! | Gaining access and finding the datagram gone | none |
//! | First access while the datagram is present | once; later unclaimed retries reuse the state |
//! | Immediate attempt | by the same rule when the access is available; none otherwise |
//! | Single last-takes candidate delivered as exclusive | none at delivery; once at [`consume`](ExclusiveDatagramDelivery::consume) |
//! | Consuming after a won competition | none |
//!
//! # Finish policies
//!
//! Each datagram uses exactly one of two finish policies, chosen by the
//! routing context:
//!
//! | Situation | Last takes | On unclaimed |
//! | --- | --- | --- |
//! | Several participants | ordinary competition | ordinary competition |
//! | One participant left, datagram present | may take it directly | still calls `try_claim` |
//! | All participants exit, datagram present | the datagram is released | the last exit hands the datagram to the continuation, once |
//! | A participant took the datagram | others observe it gone | no handoff |
//! | The winner later cancels or rejects | not refilled | not refilled, no handoff |
//!
//! Only a single-entry set under last takes is delivered directly as
//! [`DatagramDelivery::Exclusive`]; every other set, including a single entry
//! under on-unclaimed, competes through candidates.
//!
//! # Participation
//!
//! Every candidate carries one participation credential that cannot be cloned.
//! It moves into the attempt future, back into the candidate on an unclaimed
//! outcome, and into [`DatagramDelivery::Competing`] when rewrapped; it stays the
//! same credential throughout. The set of credentials is complete before any
//! candidate is delivered. Uniqueness is decided by an atomic participation
//! count, not by reference counts. A candidate that exits withdraws its wait
//! first, then releases its credential, and only then drops its private state
//! and its reference to the deliverer.
//!
//! # Thread constraints
//!
//! The base trait requires neither `Send`, `Sync` nor `'static`. Each object
//! is `Send` exactly when everything it carries is:
//!
//! | Combination | Required |
//! | --- | --- |
//! | Saving and consuming on one thread | nothing; local `Rc` state and scoped borrows work |
//! | Sharing a deliverer across threads | `Deliverer: Send + Sync` |
//! | Moving a candidate, delivery or attempt future to another thread | the whole object is `Send`: datagram, route match information, private state, deliverer |
//! | Moving private state with its single owner | `Send` only, never `Sync` |
//! | Erasing heterogeneous deliverers | checked where the concrete type is visible, see [`SendDatagramDeliverer`] |
//!
//! # Panics
//!
//! The mechanism never spawns tasks and never catches panics; ordinary
//! unwinding releases the access, because the lock guard lives in the
//! mechanism's own scope:
//!
//! | Panic | The datagram and the current participant | Other objects of the same datagram |
//! | --- | --- | --- |
//! | Preparing the candidate set | nothing was delivered; the datagram and the prepared credentials are released, no factory ran | the surrounding call unwinds |
//! | Factory or `try_claim` before the datagram is taken | the datagram stays in the shared slot; the attempt ends and must not be polled again | other candidates keep their chance |
//! | Author code after the datagram is taken | the slot stays empty; the exclusive owner drops the datagram while unwinding | other candidates observe [`DatagramClaimAttempt::ClaimedElsewhere`] |
//! | Factory during [`consume`](ExclusiveDatagramDelivery::consume) of a single candidate | the datagram belongs to the exclusive delivery and is released while unwinding | there is no competition |
//!
//! A candidate whose attempt panicked is gone with the attempt. The shared
//! datagram being intact says nothing about whether the deliverer or its
//! other state is still usable.

mod candidate;
mod deliverer;
mod delivery;
mod erased;
mod group;
pub mod queue;
mod route_match;
mod shared;

pub use self::candidate::{
    DatagramClaimAttempt, DatagramClaimCandidate, DatagramClaimFuture, DatagramClaimPrecheck,
};
pub use self::deliverer::{
    DatagramClaimAccess, DatagramClaimOutcome, DatagramDeliverer, DatagramView, ExclusiveDatagram,
};
pub use self::delivery::{DatagramAssociatedState, DatagramDelivery, ExclusiveDatagramDelivery};
pub use self::erased::{ErasedDatagramDeliverer, SendDatagramDeliverer};
pub use self::route_match::DatagramRouteMatchInfo;
pub use self::shared::UnclaimedWork;

#[cfg(test)]
mod tests;
