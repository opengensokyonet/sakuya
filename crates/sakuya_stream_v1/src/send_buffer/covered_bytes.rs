//! Stream data together with the connection credit that covers it and the
//! marker it was written with ([`CoveredBytes`]), and how the data is taken
//! from the application's input ([`TakePrefix`]).
use crate::connection_send_credit::ConnectionCreditReservation;
use bytes::{Buf, Bytes};
use nitori_io::{SplitTo, SplitToError};
use sakuya_var_int::VarInt;
use snafu::{Snafu, ensure};

/// Stream data `B`, the connection credit reservation `R` that covers
/// exactly its length, and the marker `M` the data was written with.
///
/// This is the unit a send buffer takes on append: the constructor checks
/// that the reservation's amount equals the length of the data and that the
/// length is a [`VarInt`], so a buffer receiving it need not check again.
/// The marker is the copy of the send parameters and destination the write
/// carried.
///
/// Splitting ([`SplitTo`]) cuts the data and the reservation at the same
/// length and copies the marker, so both pieces stay covered.
#[derive(Debug)]
pub struct CoveredBytes<B, R, M> {
    bytes: B,
    reservation: R,
    marker: M,
    len: VarInt,
}

impl<B: Buf, R: ConnectionCreditReservation, M> CoveredBytes<B, R, M> {
    /// Joins `bytes` with the `reservation` that covers them and the
    /// `marker` they were written with.
    ///
    /// # Errors
    ///
    /// [`CoveredBytesError`] if the length of `bytes` is not a [`VarInt`] or
    /// differs from the reservation's amount; the error hands all three
    /// inputs back.
    pub fn new(bytes: B, reservation: R, marker: M) -> Result<Self, CoveredBytesError<B, R, M>> {
        let Ok(len) = VarInt::try_from(bytes.remaining()) else {
            return covered_bytes_error::LengthOverflowSnafu {
                bytes,
                reservation,
                marker,
            }
            .fail();
        };
        let amount = reservation.amount();
        ensure!(
            amount == len,
            covered_bytes_error::AmountMismatchSnafu {
                len,
                amount,
                bytes,
                reservation,
                marker,
            }
        );
        Ok(Self {
            bytes,
            reservation,
            marker,
            len,
        })
    }
}

impl<B, R, M> CoveredBytes<B, R, M> {
    /// The length of the data, equal to the reservation's amount.
    pub fn len(&self) -> VarInt {
        self.len
    }

    /// Whether the data is empty.
    pub fn is_empty(&self) -> bool {
        self.len == VarInt::ZERO
    }

    /// The data.
    pub fn bytes(&self) -> &B {
        &self.bytes
    }

    /// The reservation covering the data.
    pub fn reservation(&self) -> &R {
        &self.reservation
    }

    /// The marker the data was written with.
    pub fn marker(&self) -> &M {
        &self.marker
    }

    /// Splits the value into the data, its reservation and its marker.
    pub fn into_parts(self) -> (B, R, M) {
        (self.bytes, self.reservation, self.marker)
    }
}

/// Cuts the first `at` bytes off together with `at` of the reservation; the
/// marker is copied onto the piece. The check comes first, so a split either
/// cuts both or changes nothing.
impl<B, R, M> SplitTo for CoveredBytes<B, R, M>
where
    B: SplitTo,
    R: ConnectionCreditReservation,
    M: Clone,
{
    fn split_to(&mut self, at: usize) -> Result<Self, SplitToError> {
        // invariant: the length is that of the data, a `usize`.
        let len = usize::try_from(self.len.get()).unwrap_or(usize::MAX);
        SplitToError::check(at, len)?;
        // invariant: `at` is within the length, a `VarInt`.
        let piece_len = VarInt::try_from(at).unwrap_or(self.len);
        // invariant: the data holds `len` bytes and the reservation owns
        // `len`, which the constructor checked, and `at <= len`, so neither
        // split fails and the value is never cut only in part.
        let bytes = match self.bytes.split_to(at) {
            Ok(bytes) => bytes,
            Err(error) => unreachable!("covered data shorter than its length: {error}"),
        };
        let reservation = match self.reservation.split_to(at) {
            Ok(reservation) => reservation,
            Err(error) => unreachable!("covering reservation below its data: {error}"),
        };
        self.len = self.len.saturating_sub(piece_len);
        Ok(Self {
            bytes,
            reservation,
            marker: self.marker.clone(),
            len: piece_len,
        })
    }
}

/// Failures of [`CoveredBytes::new`]; each hands all three inputs back
/// through [`into_parts`](Self::into_parts).
#[derive(Debug, Snafu)]
#[snafu(module(covered_bytes_error), visibility(pub(crate)))]
pub enum CoveredBytesError<B, R, M> {
    /// The length of the data is not a [`VarInt`].
    #[snafu(display("data exceeds the largest stream offset"))]
    LengthOverflow {
        /// The rejected data.
        bytes: B,
        /// The rejected reservation.
        reservation: R,
        /// The rejected marker.
        marker: M,
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
        bytes: B,
        /// The rejected reservation.
        reservation: R,
        /// The rejected marker.
        marker: M,
    },
}

impl<B, R, M> CoveredBytesError<B, R, M> {
    /// The rejected data, reservation and marker, unchanged.
    pub fn into_parts(self) -> (B, R, M) {
        match self {
            Self::LengthOverflow {
                bytes,
                reservation,
                marker,
            }
            | Self::AmountMismatch {
                bytes,
                reservation,
                marker,
                ..
            } => (bytes, reservation, marker),
        }
    }
}

/// Stream data that takes itself from the front of the application's input
/// (`TakePrefix`): what a stream sender stores of a write.
pub trait TakePrefix {
    /// Takes the first `len` bytes of `source` and advances `source` past
    /// them.
    ///
    /// The caller asks for at most `source.remaining()` bytes; an
    /// implementation may panic otherwise, as [`Buf::copy_to_bytes`] does.
    fn take_prefix(source: &mut impl Buf, len: usize) -> Self;
}

/// Through [`Buf::copy_to_bytes`]: a `Bytes` source hands over its front
/// without copying, other sources may copy.
impl TakePrefix for Bytes {
    fn take_prefix(source: &mut impl Buf, len: usize) -> Self {
        source.copy_to_bytes(len)
    }
}
