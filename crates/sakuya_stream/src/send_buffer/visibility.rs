//! The per-stream visibility settlement ([`VisibilitySettlement`]).
use super::covered_bytes::CoveredBytes;
use super::{ExposeUsageError, ExposedContent, UsageBeyondWrittenEndError, expose_usage_error};
use crate::connection_send_credit::ConnectionCreditReservation;
use crate::stream_end::{BeyondFinalSizeError, FinalSizeChangeError};
use bytes::Bytes;
use sakuya_wire::var_int::VarInt;
use snafu::{IntoError, ResultExt, Snafu, ensure};
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
#[derive(Debug)]
pub struct VisibilitySettlement<R> {
    exposure_end: VarInt,
    final_size: FinalSizeState,
    /// The reservations above the exposure end, in stream order.
    coverage: VecDeque<R>,
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

impl<R> Default for VisibilitySettlement<R> {
    fn default() -> Self {
        Self {
            exposure_end: VarInt::ZERO,
            final_size: FinalSizeState::Open,
            coverage: VecDeque::new(),
            covered: VarInt::ZERO,
        }
    }
}

impl<R: ConnectionCreditReservation> VisibilitySettlement<R> {
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
    pub fn cover(&mut self, offset: VarInt, data: CoveredBytes<R>) -> Result<Bytes, CoverError<R>> {
        if let Some(final_size) = self.final_size.established() {
            let source = FinalSizeEstablishedSnafu { final_size }.build();
            return Err(cover_error::FinalSizeEstablishedSnafu { data }.into_error(source));
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
        FinalSizeBelowExposureError::check(final_size, self.exposure_end)
            .context(fix_final_size_error::BelowExposureSnafu)?;
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
                match last.split_off(beyond) {
                    Ok(part) => drop(part),
                    // invariant: `beyond` is below the amount `last` owns.
                    Err(error) => {
                        unreachable!("cannot cancel coverage beyond the final size: {error}")
                    }
                }
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
    /// the coverage reaches the usage end. Then commits the coverage, advances the exposure end and, for
    /// an end frame, records the exposed final size.
    ///
    /// # Errors
    ///
    /// [`ExposeUsageError`] for the checks above.
    pub fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
        content: ExposedContent,
        written_end: VarInt,
    ) -> Result<VarInt, ExposeUsageError> {
        UsageBeyondWrittenEndError::check(usage_end, written_end)
            .context(expose_usage_error::BeyondWrittenEndSnafu)?;
        if let Some(final_size) = self.final_size.established() {
            if content.announces_final_size() {
                FinalSizeChangeError::check(final_size, usage_end)
                    .context(expose_usage_error::FinalSizeMismatchSnafu)?;
            } else {
                BeyondFinalSizeError::check(final_size, usage_end)
                    .context(expose_usage_error::BeyondFinalSizeSnafu)?;
            }
        }
        if content.announces_final_size() {
            FinalSizeBelowExposureError::check(usage_end, self.exposure_end)
                .context(expose_usage_error::FinalSizeBelowExposureSnafu)?;
        }

        let newly_exposed = usage_end.saturating_sub(self.exposure_end);
        if newly_exposed > VarInt::ZERO {
            UsageBeyondCoverageError::check(usage_end, self.coverage_end())
                .context(expose_usage_error::BeyondCoverageSnafu)?;
            self.commit_front(newly_exposed);
            self.exposure_end = usage_end;
        }
        if content.announces_final_size() {
            self.final_size = FinalSizeState::Exposed(usage_end);
        }
        Ok(newly_exposed)
    }

    /// Commits the first `amount` of coverage, which the caller checked.
    fn commit_front(&mut self, amount: VarInt) {
        let mut remaining = amount;
        while remaining > VarInt::ZERO {
            let Some(front) = self.coverage.front_mut() else {
                break;
            };
            let part = if front.amount() <= remaining {
                self.coverage.pop_front()
            } else {
                match front.split_off(remaining) {
                    Ok(part) => Some(part),
                    // invariant: `remaining` is below the amount `front` owns.
                    Err(error) => unreachable!("cannot split coverage to commit: {error}"),
                }
            };
            let Some(part) = part else { break };
            let committed = part.commit();
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
pub enum CoverError<R> {
    /// A final size is fixed or exposed; coverage no longer grows.
    #[snafu(display("coverage cannot grow after the final size is established"))]
    FinalSizeEstablished {
        /// The established final size.
        source: FinalSizeEstablishedError,
        /// The rejected data.
        data: CoveredBytes<R>,
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
        data: CoveredBytes<R>,
    },
    /// The coverage would end beyond [`VarInt::MAX`].
    #[snafu(display("data at offset {offset} would end beyond the largest stream offset"))]
    EndOverflow {
        /// The offset given for the data.
        offset: VarInt,
        /// The rejected data.
        data: CoveredBytes<R>,
    },
}

/// A final size is fixed or exposed, so the usage ends there and no more
/// data can follow it.
///
/// [`VisibilitySettlement::cover`] reports it through [`CoverError`], and
/// send buffers that embed the settlement through
/// [`AppendError`](super::AppendError); the error hands back no data, which
/// the carrying error holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("the final size {final_size} is established"))]
pub struct FinalSizeEstablishedError {
    final_size: VarInt,
}

impl FinalSizeEstablishedError {
    /// The established final size.
    pub const fn final_size(self) -> VarInt {
        self.final_size
    }
}

impl<R> CoverError<R> {
    /// The rejected data, unchanged.
    pub fn into_data(self) -> CoveredBytes<R> {
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
    #[snafu(display("a reset cannot take back exposed usage"))]
    BelowExposure {
        /// The rejected final size and the exposure end.
        source: FinalSizeBelowExposureError,
    },
    /// The final size differs from the one fixed or exposed before.
    #[snafu(display("a reset changes the final size"))]
    Mismatch {
        /// The final size fixed or exposed before and the rejected one.
        source: FinalSizeChangeError,
    },
}

/// A final size lies below the exposure end: usage that may already be
/// visible to the peer cannot be taken back.
///
/// The stream sender checks it for a reset it is asked for, and
/// [`VisibilitySettlement`] when it fixes or exposes a final size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("final size {final_size} lies below the exposure end {exposure_end}"))]
pub struct FinalSizeBelowExposureError {
    final_size: VarInt,
    exposure_end: VarInt,
}

impl FinalSizeBelowExposureError {
    /// Checks that `final_size` is at least `exposure_end`.
    ///
    /// # Errors
    ///
    /// [`FinalSizeBelowExposureError`] if `final_size` lies below
    /// `exposure_end`.
    pub fn check(final_size: VarInt, exposure_end: VarInt) -> Result<(), Self> {
        ensure!(
            final_size >= exposure_end,
            FinalSizeBelowExposureSnafu {
                final_size,
                exposure_end,
            }
        );
        Ok(())
    }

    /// The rejected final size, below
    /// [`exposure_end`](Self::exposure_end).
    pub const fn final_size(self) -> VarInt {
        self.final_size
    }

    /// The exposure end.
    pub const fn exposure_end(self) -> VarInt {
        self.exposure_end
    }
}

/// A usage end lies beyond the end of the stored coverage: no reservation
/// covers the usage to commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("usage end {usage_end} lies beyond the coverage ending at {coverage_end}"))]
pub struct UsageBeyondCoverageError {
    usage_end: VarInt,
    coverage_end: VarInt,
}

impl UsageBeyondCoverageError {
    /// Checks that `usage_end` is at most `coverage_end`.
    ///
    /// # Errors
    ///
    /// [`UsageBeyondCoverageError`] if `usage_end` lies beyond
    /// `coverage_end`.
    pub fn check(usage_end: VarInt, coverage_end: VarInt) -> Result<(), Self> {
        ensure!(
            usage_end <= coverage_end,
            UsageBeyondCoverageSnafu {
                usage_end,
                coverage_end,
            }
        );
        Ok(())
    }

    /// The rejected usage end, beyond [`coverage_end`](Self::coverage_end).
    pub const fn usage_end(self) -> VarInt {
        self.usage_end
    }

    /// The end of the stored coverage.
    pub const fn coverage_end(self) -> VarInt {
        self.coverage_end
    }
}
