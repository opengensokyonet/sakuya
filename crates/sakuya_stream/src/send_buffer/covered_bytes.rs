//! Stream data together with the connection credit that covers it.
use crate::connection_send_credit::ConnectionCreditReservation;
use bytes::Bytes;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};

/// Stream data and the connection credit reservation that covers exactly
/// its length.
///
/// This is the unit a send buffer takes on append: the constructor checks
/// that the reservation's amount equals the length of the data and that the
/// length is a [`VarInt`], so a buffer receiving it need not check again.
#[derive(Debug)]
pub struct CoveredBytes<R> {
    bytes: Bytes,
    reservation: R,
    len: VarInt,
}

impl<R: ConnectionCreditReservation> CoveredBytes<R> {
    /// Joins `bytes` with the `reservation` that covers them.
    ///
    /// # Errors
    ///
    /// [`CoveredBytesError`] if the length of `bytes` is not a [`VarInt`] or
    /// differs from the reservation's amount; the error hands both inputs
    /// back.
    pub fn new(bytes: Bytes, reservation: R) -> Result<Self, CoveredBytesError<R>> {
        let Ok(len) = VarInt::try_from(bytes.len()) else {
            return covered_bytes_error::LengthOverflowSnafu { bytes, reservation }.fail();
        };
        let amount = reservation.amount();
        ensure!(
            amount == len,
            covered_bytes_error::AmountMismatchSnafu {
                len,
                amount,
                bytes,
                reservation,
            }
        );
        Ok(Self {
            bytes,
            reservation,
            len,
        })
    }
}

impl<R> CoveredBytes<R> {
    /// The length of the data, equal to the reservation's amount.
    pub fn len(&self) -> VarInt {
        self.len
    }

    /// Whether the data is empty.
    pub fn is_empty(&self) -> bool {
        self.len == VarInt::ZERO
    }

    /// The data.
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// The reservation covering the data.
    pub fn reservation(&self) -> &R {
        &self.reservation
    }

    /// Splits the value into the data and its reservation.
    pub fn into_parts(self) -> (Bytes, R) {
        (self.bytes, self.reservation)
    }
}

/// Failures of [`CoveredBytes::new`]; each hands both inputs back through
/// [`into_parts`](Self::into_parts).
#[derive(Debug, Snafu)]
#[snafu(module(covered_bytes_error), visibility(pub(crate)))]
pub enum CoveredBytesError<R> {
    /// The length of the data is not a [`VarInt`].
    #[snafu(display("data of {} bytes exceeds the largest stream offset", bytes.len()))]
    LengthOverflow {
        /// The rejected data.
        bytes: Bytes,
        /// The rejected reservation.
        reservation: R,
    },
    /// The reservation's amount differs from the length of the data.
    #[snafu(display(
        "connection credit reservation of {amount} does not cover data of {len} bytes"
    ))]
    AmountMismatch {
        /// The length of the data.
        len: VarInt,
        /// The reservation's amount.
        amount: VarInt,
        /// The rejected data.
        bytes: Bytes,
        /// The rejected reservation.
        reservation: R,
    },
}

impl<R> CoveredBytesError<R> {
    /// The rejected data and reservation, unchanged.
    pub fn into_parts(self) -> (Bytes, R) {
        match self {
            Self::LengthOverflow { bytes, reservation }
            | Self::AmountMismatch {
                bytes, reservation, ..
            } => (bytes, reservation),
        }
    }
}
