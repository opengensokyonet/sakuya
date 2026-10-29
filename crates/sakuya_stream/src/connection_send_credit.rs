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
        // invariant: the amount is the sum of live reservations, each taken
        // within `L − R − C` of a `VarInt` limit, so it never exceeds the
        // limit. The fallback only keeps a stale read conservative.
        VarInt::new(self.reserved.load(Ordering::Acquire)).unwrap_or(VarInt::MAX)
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

    /// Whether this controller granted `reservation`.
    pub fn owns(&self, reservation: &ConnectionCreditReservation) -> bool {
        Arc::ptr_eq(&self.ledger, &reservation.ledger)
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
        Ok(self.reserve_available(stream_id, amount))
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
        (amount > VarInt::ZERO).then(|| self.reserve_available(stream_id, amount))
    }

    /// Reserves `amount`, which the caller checked against
    /// [`available`](Self::available).
    fn reserve_available(
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
    /// # Errors
    ///
    /// [`ForeignReservationError`] if another controller granted
    /// `reservation`; the error hands it back and nothing changes.
    pub fn commit(
        &mut self,
        reservation: ConnectionCreditReservation,
    ) -> Result<VarInt, ForeignReservationError> {
        ensure!(
            self.owns(&reservation),
            ForeignReservationSnafu { reservation }
        );
        Ok(self.commit_owned(reservation))
    }

    /// Commits `reservation`, which this controller granted.
    pub(crate) fn commit_owned(&mut self, mut reservation: ConnectionCreditReservation) -> VarInt {
        debug_assert!(self.owns(&reservation));
        let amount = reservation.take_amount();
        self.ledger.remove(amount);
        // invariant: `amount` was part of `R`, and `R + C <= L`, a `VarInt`.
        self.committed = self.committed.saturating_add(amount);
        amount
    }

    /// Releases all of `reservation`: its amount leaves `R` and becomes
    /// available.
    ///
    /// Release only usage that has never been exposed and never will be.
    /// Dropping the reservation has the same effect. Returns the released
    /// amount.
    ///
    /// # Errors
    ///
    /// [`ForeignReservationError`] if another controller granted
    /// `reservation`; the error hands it back and nothing changes.
    pub fn release(
        &mut self,
        mut reservation: ConnectionCreditReservation,
    ) -> Result<VarInt, ForeignReservationError> {
        ensure!(
            self.owns(&reservation),
            ForeignReservationSnafu { reservation }
        );
        let amount = reservation.take_amount();
        self.ledger.remove(amount);
        Ok(amount)
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
    /// # Errors
    ///
    /// [`SplitOffError`] if `amount` exceeds [`amount`](Self::amount);
    /// nothing changes then.
    pub fn split_off(&mut self, amount: VarInt) -> Result<Self, SplitOffError> {
        ensure!(
            amount <= self.amount,
            SplitOffSnafu {
                requested: amount,
                owned: self.amount,
            }
        );
        Ok(self.split_owned(amount))
    }

    /// Moves `amount`, at most [`amount`](Self::amount), into a new
    /// reservation.
    pub(crate) fn split_owned(&mut self, amount: VarInt) -> Self {
        debug_assert!(amount <= self.amount);
        self.amount = self.amount.saturating_sub(amount);
        Self {
            stream_id: self.stream_id,
            amount,
            ledger: Arc::clone(&self.ledger),
        }
    }

    /// Merges `other` into this reservation.
    ///
    /// # Errors
    ///
    /// [`AbsorbError`] if `other` belongs to another controller or another
    /// stream; the error hands `other` back and nothing changes.
    pub fn absorb(&mut self, mut other: Self) -> Result<(), AbsorbError> {
        ensure!(
            Arc::ptr_eq(&self.ledger, &other.ledger),
            absorb_error::ForeignControllerSnafu { other }
        );
        ensure!(
            self.stream_id == other.stream_id,
            absorb_error::DifferentStreamSnafu {
                stream_id: self.stream_id,
                other,
            }
        );
        let amount = other.take_amount();
        // invariant: both amounts are parts of the same controller's `R`,
        // which never exceeds its `VarInt` limit.
        self.amount = self.amount.saturating_add(amount);
        Ok(())
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

/// [`ConnectionSendFlowController::commit`] or
/// [`ConnectionSendFlowController::release`] received a reservation another
/// controller granted.
#[derive(Debug, Snafu)]
#[snafu(display(
    "connection credit reservation belongs to another connection send flow controller"
))]
pub struct ForeignReservationError {
    reservation: ConnectionCreditReservation,
}

impl ForeignReservationError {
    /// The rejected reservation, unchanged.
    pub fn into_reservation(self) -> ConnectionCreditReservation {
        self.reservation
    }
}

/// [`ConnectionCreditReservation::split_off`] asked for more than the
/// reservation owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("split of {requested} exceeds the reserved amount {owned}"))]
pub struct SplitOffError {
    /// The amount asked for.
    pub requested: VarInt,
    /// The amount the reservation owns.
    pub owned: VarInt,
}

/// Failures of [`ConnectionCreditReservation::absorb`]; each hands the
/// rejected reservation back.
#[derive(Debug, Snafu)]
#[snafu(module(absorb_error), visibility(pub(crate)))]
pub enum AbsorbError {
    /// The reservations belong to different controllers.
    #[snafu(display("connection credit reservations of different controllers cannot merge"))]
    ForeignController {
        /// The rejected reservation.
        other: ConnectionCreditReservation,
    },
    /// The reservations belong to different streams.
    #[snafu(display(
        "connection credit reservation of stream {} cannot merge into one of stream {stream_id}",
        other.stream_id()
    ))]
    DifferentStream {
        /// The stream of the reservation absorbing.
        stream_id: StreamId,
        /// The rejected reservation.
        other: ConnectionCreditReservation,
    },
}

impl AbsorbError {
    /// The rejected reservation, unchanged.
    pub fn into_other(self) -> ConnectionCreditReservation {
        match self {
            Self::ForeignController { other } | Self::DifferentStream { other, .. } => other,
        }
    }
}

#[cfg(test)]
mod tests;
