//! Connection-level send credit: the connection send flow controller
//! ([`ConnectionSendFlowController`]) and the connection credit reservations
//! ([`ConnectionCreditReservation`]) it grants.
//!
//! The peer grants one cumulative limit `L` for the stream data of all
//! streams on a connection (`initial_max_data`, then `MAX_DATA`, [RFC 9000
//! §4.1]). The controller divides the credit below that limit into two
//! amounts:
//!
//! - `R`, the reserved amount: credit taken by writes whose data has never
//!   been exposed to the peer. A reservation can still be released.
//! - `C`, the committed amount: credit whose usage may already be observed by
//!   the peer. It is never returned, also after the stream that used it is
//!   gone.
//!
//! The credit that new writes can reserve is `available = L − R − C`.
//! Reserving moves credit from `available` into `R`; committing moves it from
//! `R` into `C` without touching `available`; releasing moves it from `R` back
//! into `available`.
//!
//! A reservation is a linear handle. It cannot be cloned, splitting it
//! conserves its amount, and the controller consumes it to commit or release
//! it. Dropping a reservation cancels the part it still owns, which then
//! becomes available again; whoever owns a reservation must therefore also
//! own the right to expose the data it covers. Dropping is the cancellation
//! path for code that cannot reach the controller, such as a send buffer
//! discarding the tail after a reset; [`ConnectionSendFlowController::release`]
//! is the same cancellation performed through the controller.
//!
//! [RFC 9000 §4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use sakuya_wire::stream_id::StreamId;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};
use std::sync::Arc;

/// The connection send flow controller: the connection-wide limit on stream
/// data that the peer grants, the uncommitted reservations taken against it,
/// and the cumulative committed usage.
///
/// One controller exists per connection. Its methods take `&mut self`; the
/// stream send components that use it receive it from the composing code for
/// the duration of one operation. Reservations dropped elsewhere return their
/// credit without access to the controller, through a counter they share with
/// it.
///
/// Status: the reserve, commit and release algebra is confirmed
/// (`stream-events.md`, "连接发送额度：预留、提交与返还（已确认）"); the
/// controller's name, its sharing with streams and the connection-level
/// `DATA_BLOCKED` ownership are proposals.
pub struct ConnectionSendFlowController {
    limit: VarInt,
    committed: VarInt,
    ledger: Arc<ReservationLedger>,
}

/// The reserved amount `R`, shared with every reservation of one controller
/// so that dropping a reservation can return its credit.
struct ReservationLedger {
    reserved: AtomicU64,
}

impl ReservationLedger {
    fn reserved(&self) -> VarInt {
        // The amount never exceeds the controller's limit, a `VarInt`.
        VarInt::new(self.reserved.load(Ordering::Acquire))
            .expect("reserved credit stays below the connection limit")
    }

    fn add(&self, amount: VarInt) {
        self.reserved.fetch_add(amount.get(), Ordering::AcqRel);
    }

    fn remove(&self, amount: VarInt) {
        let previous = self.reserved.fetch_sub(amount.get(), Ordering::AcqRel);
        debug_assert!(previous >= amount.get(), "reserved credit underflow");
    }
}

impl ConnectionSendFlowController {
    /// Creates a controller whose limit is the peer's `initial_max_data`
    /// transport parameter, with nothing reserved or committed.
    pub fn new(initial_limit: VarInt) -> Self {
        Self {
            limit: initial_limit,
            committed: VarInt::ZERO,
            ledger: Arc::new(ReservationLedger {
                reserved: AtomicU64::new(0),
            }),
        }
    }

    /// The cumulative limit `L` the peer has granted.
    pub fn limit(&self) -> VarInt {
        self.limit
    }

    /// The uncommitted reserved amount `R`, summed over all streams.
    ///
    /// Reservations dropped since the last call are already deducted.
    pub fn reserved(&self) -> VarInt {
        self.ledger.reserved()
    }

    /// The cumulative committed amount `C`, including that of streams that no
    /// longer exist.
    pub fn committed(&self) -> VarInt {
        self.committed
    }

    /// The credit new writes can reserve: `L − R − C`.
    pub fn available(&self) -> VarInt {
        // `R + C <= L` holds because reserving checks it and the limit only
        // grows; the saturation guards nothing but stale reads of `R`, which
        // can only be too high.
        self.limit
            .saturating_sub(self.reserved())
            .saturating_sub(self.committed)
    }

    /// Applies a `MAX_DATA` value: the limit becomes the larger of the current
    /// limit and `limit`.
    ///
    /// Returns the previous limit if the limit grew, and `None` if `limit` did
    /// not exceed it.
    pub fn on_max_data(&mut self, limit: VarInt) -> Option<VarInt> {
        if limit > self.limit {
            Some(core::mem::replace(&mut self.limit, limit))
        } else {
            None
        }
    }

    /// Reserves exactly `amount` of connection credit for `stream_id`.
    ///
    /// # Errors
    ///
    /// [`InsufficientConnectionCreditError`] if `amount` exceeds
    /// [`available`](Self::available); nothing is reserved then.
    pub fn reserve(
        &mut self,
        stream_id: StreamId,
        amount: VarInt,
    ) -> Result<ConnectionCreditReservation, InsufficientConnectionCreditError> {
        let available = self.available();
        ensure!(
            amount <= available,
            InsufficientConnectionCreditSnafu {
                requested: amount,
                available,
            }
        );
        Ok(self.reserve_unchecked(stream_id, amount))
    }

    /// Reserves as much connection credit for `stream_id` as is available, up
    /// to `max_amount`.
    ///
    /// Returns `None` if no credit is available or `max_amount` is zero; the
    /// returned reservation's amount is never zero.
    pub fn reserve_up_to(
        &mut self,
        stream_id: StreamId,
        max_amount: VarInt,
    ) -> Option<ConnectionCreditReservation> {
        let amount = max_amount.min(self.available());
        (amount > VarInt::ZERO).then(|| self.reserve_unchecked(stream_id, amount))
    }

    fn reserve_unchecked(
        &mut self,
        stream_id: StreamId,
        amount: VarInt,
    ) -> ConnectionCreditReservation {
        self.ledger.add(amount);
        ConnectionCreditReservation {
            stream_id,
            amount,
            ledger: Arc::clone(&self.ledger),
        }
    }

    /// Commits all of `reservation`: its amount moves from `R` to `C`.
    ///
    /// Commit only at the first exposure of the usage the reservation covers;
    /// to commit part of a reservation, split that part off first with
    /// [`ConnectionCreditReservation::split_off`]. Returns the committed
    /// amount.
    ///
    /// # Panics
    ///
    /// If `reservation` was granted by another controller.
    pub fn commit(&mut self, mut reservation: ConnectionCreditReservation) -> VarInt {
        self.assert_owns(&reservation);
        let amount = reservation.take_amount();
        self.ledger.remove(amount);
        self.committed = self
            .committed
            .checked_add(amount)
            .expect("committed credit stays below the connection limit");
        amount
    }

    /// Releases all of `reservation`: its amount leaves `R` and becomes
    /// available.
    ///
    /// Release only usage that has never been exposed and never will be.
    /// Dropping the reservation has the same effect. Returns the released
    /// amount.
    ///
    /// # Panics
    ///
    /// If `reservation` was granted by another controller.
    pub fn release(&mut self, mut reservation: ConnectionCreditReservation) -> VarInt {
        self.assert_owns(&reservation);
        let amount = reservation.take_amount();
        self.ledger.remove(amount);
        amount
    }

    fn assert_owns(&self, reservation: &ConnectionCreditReservation) {
        assert!(
            Arc::ptr_eq(&self.ledger, &reservation.ledger),
            "connection credit reservation belongs to another connection send flow controller"
        );
    }
}

impl fmt::Debug for ConnectionSendFlowController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSendFlowController")
            .field("limit", &self.limit)
            .field("reserved", &self.reserved())
            .field("committed", &self.committed)
            .finish()
    }
}

/// A connection credit reservation (`connection_credit_reservation`):
/// uncommitted connection credit owned by the data of one stream.
///
/// The handle is linear: it cannot be cloned, [`split_off`](Self::split_off)
/// and [`absorb`](Self::absorb) conserve the total amount, and
/// [`ConnectionSendFlowController::commit`] or
/// [`ConnectionSendFlowController::release`] consume it. Dropping it cancels
/// the amount it still owns, which becomes available to other writes at once.
/// Moving the handle, for example into a send buffer together with the data
/// it covers, is not a cancellation.
///
/// Status: the linear form with the controller consuming the handle is the
/// one chosen among the two equivalent forms of `send-side.md`
/// ("连接流控额度预留与线性句柄"); the type's name is a proposal.
pub struct ConnectionCreditReservation {
    stream_id: StreamId,
    amount: VarInt,
    ledger: Arc<ReservationLedger>,
}

impl ConnectionCreditReservation {
    /// The stream the reservation was taken for.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// The uncommitted amount the handle owns.
    pub fn amount(&self) -> VarInt {
        self.amount
    }

    /// Moves `amount` out of this reservation into a new one for the same
    /// stream.
    ///
    /// # Panics
    ///
    /// If `amount` exceeds [`amount`](Self::amount).
    pub fn split_off(&mut self, amount: VarInt) -> Self {
        self.amount = self
            .amount
            .checked_sub(amount)
            .expect("split amount exceeds the connection credit reservation");
        Self {
            stream_id: self.stream_id,
            amount,
            ledger: Arc::clone(&self.ledger),
        }
    }

    /// Merges `other` into this reservation.
    ///
    /// # Panics
    ///
    /// If `other` belongs to another stream or another controller.
    pub fn absorb(&mut self, mut other: Self) {
        assert!(
            Arc::ptr_eq(&self.ledger, &other.ledger),
            "connection credit reservations of different controllers cannot merge"
        );
        assert_eq!(
            self.stream_id, other.stream_id,
            "connection credit reservations of different streams cannot merge"
        );
        let amount = other.take_amount();
        self.amount = self
            .amount
            .checked_add(amount)
            .expect("merged reservations stay below the connection limit");
    }

    fn take_amount(&mut self) -> VarInt {
        core::mem::replace(&mut self.amount, VarInt::ZERO)
    }
}

impl Drop for ConnectionCreditReservation {
    /// Cancels the amount the handle still owns.
    fn drop(&mut self) {
        if self.amount > VarInt::ZERO {
            self.ledger.remove(self.amount);
        }
    }
}

impl fmt::Debug for ConnectionCreditReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionCreditReservation")
            .field("stream_id", &self.stream_id)
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

/// [`ConnectionSendFlowController::reserve`] asked for more than the
/// available connection credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "{requested} bytes of connection credit requested, but only {available} are available"
))]
pub struct InsufficientConnectionCreditError {
    /// The requested amount.
    pub requested: VarInt,
    /// The credit that was available.
    pub available: VarInt,
}

#[cfg(test)]
mod tests;
