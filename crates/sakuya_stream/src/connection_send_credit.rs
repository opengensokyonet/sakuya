//! Connection-level send credit: the connection send flow controller
//! ([`ConnectionSendFlowController`]) and the connection credit reservations
//! ([`ConnectionCreditReservation`]) it grants, as traits, and their
//! implementation over shared atomic counters
//! ([`AtomicConnectionSendFlowController`],
//! [`AtomicConnectionCreditReservation`]).
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
//! The controller is shared: its methods take `&self`, and the traits only
//! state that; how an implementation synchronises, and how a dropped
//! reservation returns its credit, is the implementation's. A reservation is
//! a linear handle that only its controller grants and that keeps the shared
//! state of that controller, so the ledger changes only through the
//! controller's own reservations. It cannot be cloned, splitting it conserves
//! its amount, and it consumes itself to commit or release. Dropping a
//! reservation that was not committed is the same as releasing it; whoever
//! owns a reservation must therefore also own the right to expose the data it
//! covers.
//!
//! [RFC 9000 §4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use nitori_io::{SplitTo, SplitToError};
use sakuya_wire::v1::stream_id::StreamId;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};
use std::sync::Arc;

/// The connection send flow controller: the connection-wide limit on stream
/// data that the peer grants, the uncommitted reservations taken against it,
/// and the cumulative committed usage.
///
/// One controller exists per connection and is shared by the send direction
/// of every stream, so its methods take `&self`.
pub trait ConnectionSendFlowController {
    /// The reservation this controller grants; it commits and releases itself
    /// against this controller.
    type Reservation: ConnectionCreditReservation;

    /// The credit new writes can reserve: `L − R − C`.
    fn available(&self) -> VarInt;

    /// Reserves as much connection credit for `stream_id` as is available, up
    /// to `amount`.
    ///
    /// Returns `None` if no credit is available or `amount` is zero; the
    /// returned reservation's amount is never zero.
    fn reserve_up_to(&self, stream_id: StreamId, amount: VarInt) -> Option<Self::Reservation>;

    /// Applies a `MAX_DATA` value: the limit becomes the larger of the
    /// current limit and `maximum`.
    ///
    /// A value that is equal to or below the current limit is ignored
    /// ([RFC 9000 §4.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1)).
    /// Writes waiting for connection credit are the implementation's to wake.
    fn on_max_data(&self, maximum: VarInt);
}

/// A connection credit reservation (`connection_credit_reservation`):
/// uncommitted connection credit owned by the data of one stream.
///
/// The handle is linear: it cannot be cloned, splitting
/// ([`SplitTo::split_to`]) and [`absorb`](Self::absorb) conserve the total
/// amount, and
/// [`commit`](Self::commit) or [`release`](Self::release) consume it.
/// Dropping a reservation that was not committed has the effect of
/// [`release`](Self::release): the amount it still owns becomes available to
/// other writes at once. Moving the handle, for example into a send buffer
/// together with the data it covers, is not a cancellation.
///
/// Splitting follows nitori_io's [`SplitTo`], counting the amount in bytes of
/// stream data: [`split_to(at)`](SplitTo::split_to) moves `at` of the amount
/// into a new reservation for the same stream and fails with
/// [`SplitToError`], changing nothing, if `at`
/// exceeds the amount. The data a reservation covers is split the same way,
/// so both halves stay covered.
pub trait ConnectionCreditReservation: SplitTo {
    /// The uncommitted amount the handle owns.
    fn amount(&self) -> VarInt;

    /// Commits the whole reservation at the first exposure of the usage it
    /// covers: its amount moves from `R` to `C`. Returns the committed
    /// amount.
    ///
    /// To commit part of a reservation, split that part off first with
    /// [`split_to`](SplitTo::split_to).
    fn commit(self) -> VarInt;

    /// Releases the whole reservation: its amount leaves `R` and becomes
    /// available. Returns the released amount.
    ///
    /// Release only usage that has never been exposed and never will be.
    fn release(self) -> VarInt;

    /// Merges `other` into this reservation.
    ///
    /// # Errors
    ///
    /// [`AbsorbError`] if `other` belongs to another controller or another
    /// stream; the error hands `other` back and nothing changes.
    fn absorb(&mut self, other: Self) -> Result<(), AbsorbError<Self>>;
}

/// The counters `L`, `R` and `C`, shared by a controller and all of its
/// reservations so that dropping a reservation can return its credit.
///
/// Every access is sequentially consistent. A commit raises `C` before it
/// lowers `R`, and a reservation reads `R` before `C`: a reader that sees the
/// lowered `R` also sees the raised `C`, so a racing reader may see too
/// little credit but never too much. The compare-and-swap on `R` that takes
/// the credit fails if another reservation or release changed `R` since it
/// was read.
struct Ledger {
    limit: AtomicU64,
    reserved: AtomicU64,
    committed: AtomicU64,
}

impl Ledger {
    fn limit(&self) -> VarInt {
        // invariant: the counter only holds values stored from a `VarInt`.
        VarInt::new(self.limit.load(Ordering::SeqCst)).unwrap_or(VarInt::MAX)
    }

    fn reserved(&self) -> VarInt {
        // invariant: the amount is the sum of live reservations, each taken
        // within `L − R − C` of a `VarInt` limit, so it never exceeds the
        // limit. The fallback only keeps a stale read conservative.
        VarInt::new(self.reserved.load(Ordering::SeqCst)).unwrap_or(VarInt::MAX)
    }

    fn committed(&self) -> VarInt {
        // invariant: committed credit was part of `R`, so `R + C <= L`.
        VarInt::new(self.committed.load(Ordering::SeqCst)).unwrap_or(VarInt::MAX)
    }

    fn available(&self) -> VarInt {
        // `R + C <= L` holds because reserving checks it and the limit only
        // grows; the saturation guards nothing but stale reads of `R`, which
        // can only be too high.
        let reserved = self.reserved();
        let committed = self.committed();
        self.limit()
            .saturating_sub(reserved)
            .saturating_sub(committed)
    }

    /// Reserves `min(max_amount, available)`, which is zero if nothing can
    /// be reserved, and returns the reserved amount.
    fn reserve_up_to(&self, max_amount: VarInt) -> VarInt {
        let reserved = self
            .reserve_with(|available| Ok(max_amount.get().min(available)))
            .unwrap_or(0);
        // invariant: `reserved <= max_amount`, a `VarInt`.
        VarInt::new(reserved).unwrap_or(VarInt::MAX)
    }

    /// Reserves exactly `amount`, or nothing and returns the available
    /// credit if `amount` exceeds it.
    fn reserve_exact(&self, amount: VarInt) -> Result<(), VarInt> {
        self.reserve_with(|available| {
            if amount.get() <= available {
                Ok(amount.get())
            } else {
                Err(available)
            }
        })
        .map(|_| ())
        // invariant: the available credit is at most `L`, a `VarInt`.
        .map_err(|available| VarInt::new(available).unwrap_or(VarInt::MAX))
    }

    /// Reserves the amount `choose` picks from the available credit in one
    /// step, so a concurrent reservation never sees credit this one hands
    /// back. `choose` returning `Err` reserves nothing.
    fn reserve_with(&self, choose: impl Fn(u64) -> Result<u64, u64>) -> Result<u64, u64> {
        loop {
            let reserved = self.reserved.load(Ordering::SeqCst);
            let committed = self.committed.load(Ordering::SeqCst);
            let limit = self.limit.load(Ordering::SeqCst);
            let available = limit.saturating_sub(reserved).saturating_sub(committed);
            let amount = choose(available)?;
            if amount == 0 {
                return Ok(0);
            }
            if self
                .reserved
                .compare_exchange(
                    reserved,
                    reserved + amount,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
            {
                return Ok(amount);
            }
        }
    }

    fn commit(&self, amount: VarInt) {
        self.committed.fetch_add(amount.get(), Ordering::SeqCst);
        self.remove_reserved(amount);
    }

    fn remove_reserved(&self, amount: VarInt) {
        let previous = self.reserved.fetch_sub(amount.get(), Ordering::SeqCst);
        debug_assert!(previous >= amount.get(), "reserved credit underflow");
    }
}

/// The connection send flow controller over shared atomic counters.
///
/// One controller exists per connection; the send direction of each stream
/// holds it in an [`Arc`]. Reservations keep the counters alive and return
/// their credit through them when dropped, without access to the controller.
pub struct AtomicConnectionSendFlowController {
    ledger: Arc<Ledger>,
}

impl AtomicConnectionSendFlowController {
    /// Creates a controller whose limit is the peer's `initial_max_data`
    /// transport parameter, with nothing reserved or committed.
    pub fn new(initial_limit: VarInt) -> Self {
        Self {
            ledger: Arc::new(Ledger {
                limit: AtomicU64::new(initial_limit.get()),
                reserved: AtomicU64::new(0),
                committed: AtomicU64::new(0),
            }),
        }
    }

    /// The cumulative limit `L` the peer has granted.
    pub fn limit(&self) -> VarInt {
        self.ledger.limit()
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
        self.ledger.committed()
    }

    /// Reserves exactly `amount` of connection credit for `stream_id`.
    ///
    /// # Errors
    ///
    /// [`InsufficientConnectionCreditError`] if `amount` exceeds
    /// [`available`](ConnectionSendFlowController::available); nothing is
    /// reserved then.
    pub fn reserve(
        &self,
        stream_id: StreamId,
        amount: VarInt,
    ) -> Result<AtomicConnectionCreditReservation, InsufficientConnectionCreditError> {
        if let Err(available) = self.ledger.reserve_exact(amount) {
            return InsufficientConnectionCreditSnafu {
                requested: amount,
                available,
            }
            .fail();
        }
        Ok(self.reservation(stream_id, amount))
    }

    fn reservation(
        &self,
        stream_id: StreamId,
        amount: VarInt,
    ) -> AtomicConnectionCreditReservation {
        AtomicConnectionCreditReservation {
            stream_id,
            amount,
            ledger: Arc::clone(&self.ledger),
        }
    }
}

impl ConnectionSendFlowController for AtomicConnectionSendFlowController {
    type Reservation = AtomicConnectionCreditReservation;

    fn available(&self) -> VarInt {
        self.ledger.available()
    }

    fn reserve_up_to(&self, stream_id: StreamId, amount: VarInt) -> Option<Self::Reservation> {
        let reserved = self.ledger.reserve_up_to(amount);
        (reserved > VarInt::ZERO).then(|| self.reservation(stream_id, reserved))
    }

    fn on_max_data(&self, maximum: VarInt) {
        self.ledger.limit.fetch_max(maximum.get(), Ordering::SeqCst);
    }
}

impl fmt::Debug for AtomicConnectionSendFlowController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AtomicConnectionSendFlowController")
            .field("limit", &self.limit())
            .field("reserved", &self.reserved())
            .field("committed", &self.committed())
            .finish()
    }
}

/// A connection credit reservation granted by an
/// [`AtomicConnectionSendFlowController`].
///
/// Dropping it without committing releases the amount it still owns.
pub struct AtomicConnectionCreditReservation {
    stream_id: StreamId,
    amount: VarInt,
    ledger: Arc<Ledger>,
}

impl AtomicConnectionCreditReservation {
    /// The stream the reservation was taken for.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    fn take_amount(&mut self) -> VarInt {
        core::mem::replace(&mut self.amount, VarInt::ZERO)
    }
}

impl ConnectionCreditReservation for AtomicConnectionCreditReservation {
    fn amount(&self) -> VarInt {
        self.amount
    }

    fn commit(mut self) -> VarInt {
        let amount = self.take_amount();
        self.ledger.commit(amount);
        amount
    }

    fn release(mut self) -> VarInt {
        let amount = self.take_amount();
        self.ledger.remove_reserved(amount);
        amount
    }

    fn absorb(&mut self, mut other: Self) -> Result<(), AbsorbError<Self>> {
        ensure!(
            Arc::ptr_eq(&self.ledger, &other.ledger),
            absorb_error::ForeignControllerSnafu { other }
        );
        ensure!(
            self.stream_id == other.stream_id,
            absorb_error::DifferentStreamSnafu {
                stream_id: self.stream_id,
                other_stream_id: other.stream_id,
                other,
            }
        );
        let amount = other.take_amount();
        // invariant: both amounts are parts of the same controller's `R`,
        // which never exceeds its `VarInt` limit.
        self.amount = self.amount.saturating_add(amount);
        Ok(())
    }
}

/// The amount is converted at this boundary: `at` counts bytes of stream
/// data as a `usize`, the amount is a [`VarInt`].
impl SplitTo for AtomicConnectionCreditReservation {
    fn split_to(&mut self, at: usize) -> Result<Self, SplitToError> {
        // An amount that a `usize` cannot hold, possible only where `usize`
        // is narrower than 62 bits, is larger than every `at`. Comparing
        // with `usize::MAX` instead accepts exactly the same `at`, and the
        // substitute never appears in an error: no `at` exceeds it.
        let owned = usize::try_from(self.amount.get()).unwrap_or(usize::MAX);
        SplitToError::check(at, owned)?;
        // invariant: `at <= owned <= amount`, a `VarInt`.
        let at = VarInt::try_from(at).unwrap_or(self.amount);
        self.amount = self.amount.saturating_sub(at);
        Ok(Self {
            stream_id: self.stream_id,
            amount: at,
            ledger: Arc::clone(&self.ledger),
        })
    }
}

impl Drop for AtomicConnectionCreditReservation {
    /// Releases the amount the handle still owns.
    fn drop(&mut self) {
        if self.amount > VarInt::ZERO {
            self.ledger.remove_reserved(self.amount);
        }
    }
}

impl fmt::Debug for AtomicConnectionCreditReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AtomicConnectionCreditReservation")
            .field("stream_id", &self.stream_id)
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

/// [`AtomicConnectionSendFlowController::reserve`] asked for more than the
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

/// Failures of [`ConnectionCreditReservation::absorb`]; each hands the
/// rejected reservation `R` back.
#[derive(Debug, Snafu)]
#[snafu(module(absorb_error), visibility(pub(crate)))]
pub enum AbsorbError<R> {
    /// The reservations belong to different controllers.
    #[snafu(display("connection credit reservations of different controllers cannot merge"))]
    ForeignController {
        /// The rejected reservation.
        other: R,
    },
    /// The reservations belong to different streams.
    #[snafu(display(
        "connection credit reservation of stream {other_stream_id} cannot merge into one of stream {stream_id}"
    ))]
    DifferentStream {
        /// The stream of the reservation absorbing.
        stream_id: StreamId,
        /// The stream of the rejected reservation.
        other_stream_id: StreamId,
        /// The rejected reservation.
        other: R,
    },
}

impl<R> AbsorbError<R> {
    /// The rejected reservation, unchanged.
    pub fn into_other(self) -> R {
        match self {
            Self::ForeignController { other } | Self::DifferentStream { other, .. } => other,
        }
    }
}

#[cfg(test)]
mod tests;
