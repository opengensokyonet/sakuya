//! Claim delivery: how the candidates of one datagram compete for it
//!
//! Routing a received datagram yields a frozen set of route entries. For each
//! entry the mechanism builds one [`DatagramClaimCandidate`] and hands it to the
//! entry's [`DatagramDeliverer`] through [`DatagramDeliverer::deliver`]. All
//! candidates of one datagram share a private core that holds the single
//! original datagram and counts the candidates still participating. A candidate
//! keeps that core and the [route match information](route_match) of its
//! entry, and nothing else: it refers to no deliverer and stores no judgment
//! state.
//!
//! The deliverer only delivers. The synchronous claim judgment is not part of
//! the deliverer: whoever holds a competing candidate after delivery passes
//! its own judgment to [`DatagramClaimCandidate::try_exclusive`], and decides
//! what goes into it and what comes out. The mechanism owns the candidate
//! shell, the access to the shared datagram and every ownership transfer. A
//! deliverer of a routing domain that hands unclaimed datagrams off also names
//! that domain's [`UnclaimedHandoff`] as its
//! [`Handoff`](deliverer::DatagramDeliverer::Handoff). Neither delivery nor the
//! judgment waits. Waiting for business conditions, such as keys or
//! configuration, belongs to whoever holds the candidate.
//!
//! # One attempt
//!
//! [`DatagramClaimCandidate::try_exclusive`] moves the candidate and the
//! judgment into a lazy future. On first poll the future waits for the shared
//! access (a `tokio::sync::Mutex` around the datagram slot), then, in one
//! synchronous section without awaiting:
//!
//! 1. if the datagram uses the [last-takes](#finish-policies) finish policy and
//!    this candidate is the only remaining participant, it takes the datagram
//!    and yields [`DatagramClaimAttempt::Exclusive`] without calling the
//!    judgment, or [`DatagramClaimAttempt::ClaimedElsewhere`] if it is already
//!    gone;
//! 2. otherwise, if the datagram is already gone, it yields
//!    [`DatagramClaimAttempt::ClaimedElsewhere`] without calling the judgment;
//! 3. otherwise it calls the judgment once with a [`DatagramClaimAccess`] and
//!    the candidate's route match information.
//!
//! The judgment returns a [`DatagramClaimOutcome`]:
//!
//! | Outcome | Attempt |
//! | --- | --- |
//! | `Claimed`, with the datagram taken through [`into_exclusive`](candidate::DatagramClaimAccess::into_exclusive) and a value | [`Claimed`](candidate::DatagramClaimAttempt::Claimed): an exclusive delivery and the value |
//! | `Unclaimed`, with the unchanged access | [`Unclaimed`](candidate::DatagramClaimAttempt::Unclaimed): the access is released and the same candidate comes back |
//! | `Abandoned`, with a value | [`Abandoned`](candidate::DatagramClaimAttempt::Abandoned): the candidate exits and the value comes back |
//!
//! The access is released before the attempt completes. The judgment must
//! accept the access for every lifetime, and the values it returns have
//! types chosen outside it, so neither the access nor the
//! [`ClaimedDatagram`] taken from it can leave the judgment, and `Claimed`
//! accepts no datagram other than the one taken from this access. The access
//! is also neither `Send` nor `Sync`. The judgment may capture anything, for
//! example a handle to its caller's state that it reads while it decides.
//!
//! Dropping the future before its first poll exits the candidate without a
//! judgment; dropping it while it waits first withdraws the wait, which passes
//! the access on to the next waiter, and then exits the candidate. Pausing
//! means keeping the same pinned future.
//! [`DatagramClaimCandidate::try_exclusive_now`] performs the same synchronous
//! section only if the access is immediately available, and otherwise hands
//! the candidate and the judgment back.
//!
//! # Finish policies
//!
//! Each datagram uses exactly one of two finish policies, chosen by the
//! routing context:
//!
//! | Situation | Last takes | On unclaimed |
//! | --- | --- | --- |
//! | Several participants | ordinary competition | ordinary competition |
//! | One participant left, datagram present | may take it directly | still calls the judgment |
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
//! first and then releases its credential; an abandoned judgment is an exit.
//!
//! # Thread constraints
//!
//! The base trait requires neither `Send`, `Sync` nor `'static`. Each object
//! is `Send` exactly when everything it carries is:
//!
//! | Combination | Required |
//! | --- | --- |
//! | Saving and consuming on one thread | nothing; local `Rc` datagrams, judgments and scoped borrows work |
//! | Sharing a deliverer across threads | `Deliverer: Send + Sync` |
//! | Moving a candidate or delivery to another thread | the whole object is `Send`: datagram, route match information, and for a candidate the domain's handoff |
//! | Moving an attempt future to another thread | the candidate and the judgment with everything it captures are `Send` |
//! | Handing unclaimed datagrams off | nothing; a local handoff makes the candidates local, a `Send` handoff keeps them `Send` |
//! | Erasing heterogeneous deliverers | checked where the concrete type is visible, see [`SendDatagramDeliverer`] |
//!
//! The access exists only inside the synchronous judgment and never across
//! an await, so it does not decide whether an attempt future can move.
//!
//! # Panics
//!
//! The mechanism never spawns tasks and never catches panics; ordinary
//! unwinding releases the access, because the lock guard lives in the
//! mechanism's own scope:
//!
//! | Panic | The datagram and the current participant | Other objects of the same datagram |
//! | --- | --- | --- |
//! | Preparing the candidate set | nothing was delivered; the datagram and the prepared credentials are released, no judgment ran | the surrounding call unwinds |
//! | Judgment before the datagram is taken | the datagram stays in the shared slot; the attempt ends and must not be polled again | other candidates keep their chance |
//! | Judgment after the datagram is taken | the slot stays empty; the exclusive owner drops the datagram while unwinding | other candidates observe [`DatagramClaimAttempt::ClaimedElsewhere`] |
//!
//! A candidate whose attempt panicked is gone with the attempt. The shared
//! datagram being intact says nothing about whether the caller's state is
//! still usable. The judgment and its locals may be dropped before the access
//! is released, so their destructors must not wait for or re-enter it either.
//!
//! [`DatagramClaimCandidate`]: candidate::DatagramClaimCandidate
//! [`DatagramClaimCandidate::try_exclusive`]: candidate::DatagramClaimCandidate::try_exclusive
//! [`DatagramClaimCandidate::try_exclusive_now`]: candidate::DatagramClaimCandidate::try_exclusive_now
//! [`DatagramClaimAttempt::Exclusive`]: candidate::DatagramClaimAttempt::Exclusive
//! [`DatagramClaimAttempt::ClaimedElsewhere`]: candidate::DatagramClaimAttempt::ClaimedElsewhere
//! [`DatagramClaimAttempt`]: candidate::DatagramClaimAttempt
//! [`ClaimedDatagram`]: candidate::ClaimedDatagram
//! [`DatagramClaimAccess`]: candidate::DatagramClaimAccess
//! [`DatagramClaimOutcome`]: candidate::DatagramClaimOutcome
//! [`DatagramDeliverer`]: deliverer::DatagramDeliverer
//! [`DatagramDeliverer::deliver`]: deliverer::DatagramDeliverer::deliver
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
