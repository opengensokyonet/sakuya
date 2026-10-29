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
//! - [`new_datagram_state`](deliverer::DatagramDeliverer::new_datagram_state)
//!   builds the initial private state from a read-only [`DatagramView`];
//! - [`try_claim`](deliverer::DatagramDeliverer::try_claim) decides, within one
//!   synchronous access, whether to take the datagram through
//!   [`DatagramClaimAccess::into_exclusive`];
//! - [`deliver`](deliverer::DatagramDeliverer::deliver) consumes a
//!   [`DatagramDelivery`] and returns unit.
//!
//! A deliverer of a routing domain that hands unclaimed datagrams off also
//! names that domain's [`UnclaimedHandoff`] as its
//! [`Handoff`](deliverer::DatagramDeliverer::Handoff). None of the capabilities
//! waits. Waiting for business conditions, such as keys or configuration,
//! belongs to whoever holds the candidate.
//!
//! # One attempt
//!
//! [`DatagramClaimCandidate::try_exclusive`] moves the candidate into a lazy
//! future. On first poll the future waits for the shared access
//! (a `tokio::sync::Mutex` around the datagram slot), then, in one synchronous
//! section without awaiting:
//!
//! 1. if the datagram is already gone, it yields
//!    [`DatagramClaimAttempt::ClaimedElsewhere`] without calling the factory;
//! 2. if the datagram uses the [last-takes](#finish-policies) finish policy and
//!    this candidate is the only remaining participant, it takes the datagram
//!    directly without calling `try_claim`, and then calls the factory once
//!    with a read-only view of the datagram if the candidate's private state
//!    is not initialized yet;
//! 3. otherwise, if the private state is not initialized yet, it calls the
//!    factory once with a read-only view of the datagram, and then calls the
//!    deliverer's `try_claim`. An unclaimed outcome stores the updated state
//!    back into the same candidate.
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
//! | Single last-takes candidate delivered as exclusive | none at delivery; once at [`consume`](delivery::ExclusiveDatagramDelivery::consume) |
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
//! | All participants exit, datagram present | the datagram is released | the last exit passes the datagram to the domain's [`UnclaimedHandoff`], once |
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
//! | Moving a candidate, delivery or attempt future to another thread | the whole object is `Send`: datagram, route match information, private state, deliverer, and for a candidate the domain's handoff |
//! | Handing unclaimed datagrams off | nothing; a local handoff makes the candidates local, a `Send` handoff keeps them `Send` |
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
//! | Factory of a sole last-takes participant | the datagram was already taken and is released while unwinding, as the participant's exit would release it | there is no other participant |
//! | Factory during [`consume`](delivery::ExclusiveDatagramDelivery::consume) of a single candidate | the datagram belongs to the exclusive delivery and is released while unwinding | there is no competition |
//!
//! A candidate whose attempt panicked is gone with the attempt. The shared
//! datagram being intact says nothing about whether the deliverer or its
//! other state is still usable.
//!
//! [`DatagramClaimCandidate`]: candidate::DatagramClaimCandidate
//! [`DatagramClaimCandidate::try_exclusive`]: candidate::DatagramClaimCandidate::try_exclusive
//! [`DatagramClaimCandidate::try_exclusive_now`]: candidate::DatagramClaimCandidate::try_exclusive_now
//! [`DatagramClaimAttempt::ClaimedElsewhere`]: candidate::DatagramClaimAttempt::ClaimedElsewhere
//! [`DatagramDeliverer`]: deliverer::DatagramDeliverer
//! [`DatagramDeliverer::deliver`]: deliverer::DatagramDeliverer::deliver
//! [`DatagramView`]: deliverer::DatagramView
//! [`DatagramClaimAccess::into_exclusive`]: deliverer::DatagramClaimAccess::into_exclusive
//! [`DatagramDelivery`]: delivery::DatagramDelivery
//! [`DatagramDelivery::Exclusive`]: delivery::DatagramDelivery::Exclusive
//! [`DatagramDelivery::Competing`]: delivery::DatagramDelivery::Competing
//! [`SendDatagramDeliverer`]: erased::SendDatagramDeliverer
//! [`UnclaimedHandoff`]: finish::UnclaimedHandoff

pub mod candidate;
pub mod deliverer;
pub mod delivery;
pub mod erased;
pub mod finish;
pub(crate) mod group;
pub mod queue;
pub mod route_match;
pub(crate) mod shared;

#[cfg(test)]
mod tests;
