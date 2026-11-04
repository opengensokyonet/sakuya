//! The per-stream visibility settlement ([`VisibilitySettlement`]).
use super::covered_bytes::CoveredBytes;
use super::{ExposeUsageError, ExposedEnd, expose_usage_error};
use crate::connection_send_credit::{ConnectionCreditReservation, ConnectionSendFlowController};
use crate::stream_end::{BeyondFinalSizeError, FinalSizeChangeError};
use bytes::Bytes;
use sakuya_wire::var_int::VarInt;
use snafu::{ResultExt, Snafu, ensure};
use std::collections::VecDeque;

/// The per-stream visibility settlement: the exposure end, the final size
/// and the uncommitted connection credit coverage above the exposure end.
///
/// STREAM data, a FIN and a reset all settle through
/// [`expose_usage_through`](Self::expose_usage_through), so that no sending
/// path keeps its own copy of the exposure end or commits credit by payload
/// length. The coverage is contiguous: it starts at the exposure end and
/// grows by each covered append.
///
/// Send buffer implementations can embed this settlement instead of
/// reimplementing it; it is the fixed part of the accounting.
///
/// # Final size
///
/// The settlement knows the final size in one of three ways:
///
/// ```text
///            fix_final_size(f)              expose(f, FinalSize)
///   Open ────────────────────▶ Fixed(f) ─────────────────────▶ Exposed(f)
///     │                                                            ▲
///     └────────────────────── expose(f, FinalSize) ───────────────┘
/// ```
///
/// Coverage grows only while the final size is open. Fixing cancels the
/// coverage beyond the final size; fixing an exposed final size again with
/// the same value cancels what remains beyond it.
#[derive(Debug, Default)]
pub struct VisibilitySettlement {
    exposure_end: VarInt,
    final_size: FinalSizeState,
    /// The reservations above the exposure end, in stream order.
    coverage: VecDeque<ConnectionCreditReservation>,
    /// The sum of the amounts in `coverage`.
    covered: VarInt,
}

/// What the settlement knows about the final size.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum FinalSizeState {
    /// No final size is established; coverage may grow.
    #[default]
    Open,
    /// A reset fixed the final size, which has not been exposed.
    Fixed(VarInt),
    /// A FIN or reset exposed the final size.
    Exposed(VarInt),
}

impl FinalSizeState {
    fn established(self) -> Option<VarInt> {
        match self {
            Self::Open => None,
            Self::Fixed(final_size) | Self::Exposed(final_size) => Some(final_size),
        }
    }
}

impl VisibilitySettlement {
    /// Creates the settlement of a stream with nothing exposed or covered.
    pub fn new() -> Self {
        Self::default()
    }

    /// The exposure end `E`.
    pub fn exposure_end(&self) -> VarInt {
        self.exposure_end
    }

    /// The final size a FIN or reset has exposed, if any.
    pub fn exposed_final_size(&self) -> Option<VarInt> {
        match self.final_size {
            FinalSizeState::Exposed(final_size) => Some(final_size),
            FinalSizeState::Open | FinalSizeState::Fixed(_) => None,
        }
    }

    /// The final size fixed or exposed, if any.
    pub fn final_size(&self) -> Option<VarInt> {
        self.final_size.established()
    }

    /// The uncommitted amount of the coverage.
    pub fn covered(&self) -> VarInt {
        self.covered
    }

    /// The end of the uncommitted coverage: the exposure end plus the
    /// reserved amount above it.
    pub fn coverage_end(&self) -> VarInt {
        // invariant: `cover` admits coverage only while the sum stays a
        // `VarInt`, and exposure moves amounts from `covered` to `E`.
        self.exposure_end.saturating_add(self.covered)
    }

    /// Extends the coverage by the reservation of `data`, which covers the
    /// usage starting at `offset`, and returns the data without its
    /// reservation.
    ///
    /// # Errors
    ///
    /// [`CoverError`] if a final size is established, if `offset` is not the
    /// [`coverage_end`](Self::coverage_end), or if the coverage would end
    /// beyond [`VarInt::MAX`]; the error hands `data` back and nothing
    /// changes.
    pub fn cover(&mut self, offset: VarInt, data: CoveredBytes) -> Result<Bytes, CoverError> {
        if let Some(final_size) = self.final_size.established() {
            return cover_error::FinalSizeEstablishedSnafu { final_size, data }.fail();
        }
        let coverage_end = self.coverage_end();
        ensure!(
            offset == coverage_end,
            cover_error::NotContiguousSnafu {
                offset,
                coverage_end,
                data,
            }
        );
        let Some(covered) = self.covered.checked_add(data.len()) else {
            return cover_error::EndOverflowSnafu { offset, data }.fail();
        };
        if self.exposure_end.checked_add(covered).is_none() {
            return cover_error::EndOverflowSnafu { offset, data }.fail();
        }
        let (bytes, reservation) = data.into_parts();
        self.covered = covered;
        if reservation.amount() > VarInt::ZERO {
            self.coverage.push_back(reservation);
        }
        Ok(bytes)
    }

    /// Fixes the final size of a reset: keeps the coverage below
    /// `final_size` and cancels the reservations beyond it.
    ///
    /// Later exposures cannot pass `final_size`. Repeating the call with the
    /// same final size releases nothing.
    ///
    /// # Errors
    ///
    /// [`FixFinalSizeError`] if `final_size` lies below the exposure end or
    /// differs from a final size fixed or exposed before; nothing changes
    /// then.
    pub fn fix_final_size(&mut self, final_size: VarInt) -> Result<(), FixFinalSizeError> {
        ensure!(
            final_size >= self.exposure_end,
            fix_final_size_error::BelowExposureSnafu {
                final_size,
                exposure_end: self.exposure_end,
            }
        );
        if let Some(established) = self.final_size.established() {
            FinalSizeChangeError::check(established, final_size)
                .context(fix_final_size_error::MismatchSnafu)?;
        } else {
            self.final_size = FinalSizeState::Fixed(final_size);
        }
        // Dropping cancels the reservations: this usage is never exposed.
        let kept = final_size.saturating_sub(self.exposure_end);
        let mut beyond = self.covered.saturating_sub(kept);
        while beyond > VarInt::ZERO {
            let Some(last) = self.coverage.back_mut() else {
                break;
            };
            let cancelled = if last.amount() <= beyond {
                let amount = last.amount();
                self.coverage.pop_back();
                amount
            } else {
                drop(last.split_owned(beyond));
                beyond
            };
            beyond = beyond.saturating_sub(cancelled);
            self.covered = self.covered.saturating_sub(cancelled);
        }
        Ok(())
    }

    /// Settles an exposure of usage up to `usage_end` and commits the newly
    /// exposed coverage: `max(E, usage_end) − E`, returned.
    ///
    /// Checks, before anything changes, that the usage end does not pass the
    /// written end or a fixed or exposed final size, that a final size agrees
    /// with an established one and is not below the exposure end, and that
    /// the coverage reaches the usage end with reservations `connection`
    /// granted. Then commits the coverage, advances the exposure end and, for
    /// [`ExposedEnd::FinalSize`], records the exposed final size.
    ///
    /// # Errors
    ///
    /// [`ExposeUsageError`] for the checks above.
    pub fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
        end: ExposedEnd,
        written_end: VarInt,
        connection: &mut ConnectionSendFlowController,
    ) -> Result<VarInt, ExposeUsageError> {
        ensure!(
            usage_end <= written_end,
            expose_usage_error::BeyondWrittenEndSnafu {
                usage_end,
                written_end,
            }
        );
        if let Some(final_size) = self.final_size.established() {
            match end {
                ExposedEnd::Data => BeyondFinalSizeError::check(final_size, usage_end)
                    .context(expose_usage_error::BeyondFinalSizeSnafu)?,
                ExposedEnd::FinalSize => FinalSizeChangeError::check(final_size, usage_end)
                    .context(expose_usage_error::FinalSizeMismatchSnafu)?,
            }
        }
        if end == ExposedEnd::FinalSize {
            ensure!(
                usage_end >= self.exposure_end,
                expose_usage_error::FinalSizeBelowExposureSnafu {
                    final_size: usage_end,
                    exposure_end: self.exposure_end,
                }
            );
        }

        let newly_exposed = usage_end.saturating_sub(self.exposure_end);
        if newly_exposed > VarInt::ZERO {
            ensure!(
                newly_exposed <= self.covered,
                expose_usage_error::BeyondCoverageSnafu {
                    usage_end,
                    coverage_end: self.coverage_end(),
                }
            );
            self.check_owner(newly_exposed, connection)?;
            self.commit_front(newly_exposed, connection);
            self.exposure_end = usage_end;
        }
        if end == ExposedEnd::FinalSize {
            self.final_size = FinalSizeState::Exposed(usage_end);
        }
        Ok(newly_exposed)
    }

    /// Checks that `connection` granted every reservation the first `amount`
    /// of coverage takes from.
    fn check_owner(
        &self,
        amount: VarInt,
        connection: &ConnectionSendFlowController,
    ) -> Result<(), ExposeUsageError> {
        let mut remaining = amount;
        for reservation in &self.coverage {
            if remaining == VarInt::ZERO {
                break;
            }
            ensure!(
                connection.owns(reservation),
                expose_usage_error::ForeignReservationSnafu
            );
            remaining = remaining.saturating_sub(reservation.amount());
        }
        Ok(())
    }

    /// Commits the first `amount` of coverage, which the caller checked.
    fn commit_front(&mut self, amount: VarInt, connection: &mut ConnectionSendFlowController) {
        let mut remaining = amount;
        while remaining > VarInt::ZERO {
            let Some(front) = self.coverage.front_mut() else {
                break;
            };
            let part = if front.amount() <= remaining {
                self.coverage.pop_front()
            } else {
                Some(front.split_owned(remaining))
            };
            let Some(part) = part else { break };
            let committed = connection.commit_owned(part);
            remaining = remaining.saturating_sub(committed);
            self.covered = self.covered.saturating_sub(committed);
        }
        debug_assert_eq!(remaining, VarInt::ZERO);
    }
}

/// Failures of [`VisibilitySettlement::cover`]; each hands the data back
/// through [`into_data`](Self::into_data).
#[derive(Debug, Snafu)]
#[snafu(module(cover_error), visibility(pub(crate)))]
pub enum CoverError {
    /// A final size is fixed or exposed; coverage no longer grows.
    #[snafu(display("coverage cannot grow after the final size {final_size} is established"))]
    FinalSizeEstablished {
        /// The established final size.
        final_size: VarInt,
        /// The rejected data.
        data: CoveredBytes,
    },
    /// The data does not start at the coverage end.
    #[snafu(display(
        "data at offset {offset} does not continue the coverage ending at {coverage_end}"
    ))]
    NotContiguous {
        /// The offset given for the data.
        offset: VarInt,
        /// The coverage end.
        coverage_end: VarInt,
        /// The rejected data.
        data: CoveredBytes,
    },
    /// The coverage would end beyond [`VarInt::MAX`].
    #[snafu(display("data at offset {offset} would end beyond the largest stream offset"))]
    EndOverflow {
        /// The offset given for the data.
        offset: VarInt,
        /// The rejected data.
        data: CoveredBytes,
    },
}

impl CoverError {
    /// The rejected data, unchanged.
    pub fn into_data(self) -> CoveredBytes {
        match self {
            Self::FinalSizeEstablished { data, .. }
            | Self::NotContiguous { data, .. }
            | Self::EndOverflow { data, .. } => data,
        }
    }
}

/// Failures of [`VisibilitySettlement::fix_final_size`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(fix_final_size_error), visibility(pub(crate)))]
pub enum FixFinalSizeError {
    /// The final size lies below the exposure end.
    #[snafu(display("final size {final_size} lies below the exposure end {exposure_end}"))]
    BelowExposure {
        /// The rejected final size.
        final_size: VarInt,
        /// The exposure end.
        exposure_end: VarInt,
    },
    /// The final size differs from the one fixed or exposed before.
    #[snafu(display("a reset changes the final size"))]
    Mismatch {
        /// The final size fixed or exposed before and the rejected one.
        source: FinalSizeChangeError,
    },
}
