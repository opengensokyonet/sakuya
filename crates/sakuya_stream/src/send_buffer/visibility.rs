use super::{ExposeUsageError, ExposedEnd, expose_usage_error};
use crate::connection_send_credit::{ConnectionCreditReservation, ConnectionSendFlowController};
use sakuya_wire::var_int::VarInt;
use snafu::ensure;

/// The per-stream visibility settlement: the exposure end, the exposed final
/// size and the uncommitted connection credit coverage above the exposure
/// end.
///
/// STREAM data, a FIN and a reset all settle through
/// [`expose_usage_through`](Self::expose_usage_through), so that no sending
/// path keeps its own copy of the exposure end or commits credit by payload
/// length. The coverage is contiguous: it starts at the exposure end and
/// grows by each appended reservation.
///
/// Send buffer implementations can embed this settlement instead of
/// reimplementing it; it is the fixed part of the accounting.
///
/// Status: proposal (`send-accounting.md`, "每流可见性结算职责（建议待确认）");
/// the settlement steps are candidates.
#[derive(Debug, Default)]
pub struct VisibilitySettlement {
    exposure_end: VarInt,
    exposed_final_size: Option<VarInt>,
    fixed_final_size: Option<VarInt>,
    coverage: Option<ConnectionCreditReservation>,
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
        self.exposed_final_size
    }

    /// The end of the uncommitted coverage: the exposure end plus the
    /// reserved amount above it.
    pub fn coverage_end(&self) -> VarInt {
        let covered = self
            .coverage
            .as_ref()
            .map_or(VarInt::ZERO, ConnectionCreditReservation::amount);
        self.exposure_end.saturating_add(covered)
    }

    /// Extends the coverage by `reservation`, which covers the usage starting
    /// at `offset`.
    ///
    /// # Panics
    ///
    /// If `offset` is not the current [`coverage_end`](Self::coverage_end),
    /// or if a final size has been fixed.
    pub fn cover(&mut self, offset: VarInt, reservation: ConnectionCreditReservation) {
        assert!(
            self.fixed_final_size.is_none(),
            "coverage cannot grow after the final size is fixed"
        );
        assert_eq!(
            offset,
            self.coverage_end(),
            "connection credit coverage must stay contiguous"
        );
        match &mut self.coverage {
            Some(coverage) => coverage.absorb(reservation),
            None => self.coverage = Some(reservation),
        }
    }

    /// Fixes the final size of a reset: keeps the coverage below
    /// `final_size` and cancels the reservations beyond it.
    ///
    /// Later exposures cannot pass `final_size`. Repeating the call with the
    /// same final size releases nothing.
    ///
    /// # Panics
    ///
    /// If `final_size` lies below the exposure end or differs from a final
    /// size fixed before.
    pub fn fix_final_size(&mut self, final_size: VarInt) {
        assert!(
            final_size >= self.exposure_end,
            "a final size cannot lie below the exposure end"
        );
        if let Some(fixed) = self.fixed_final_size {
            assert_eq!(fixed, final_size, "a fixed final size cannot change");
        }
        self.fixed_final_size = Some(final_size);
        if let Some(coverage) = &mut self.coverage {
            let kept = final_size.saturating_sub(self.exposure_end);
            if let Some(beyond) = coverage.amount().checked_sub(kept) {
                // Dropping cancels the reservation: this usage is never
                // exposed.
                drop(coverage.split_off(beyond));
            }
        }
    }

    /// Settles an exposure of usage up to `usage_end` and commits the newly
    /// exposed coverage: `max(E, usage_end) − E`, returned.
    ///
    /// Checks, before anything changes, that the usage end does not pass the
    /// written end or a fixed or exposed final size, that a final size agrees
    /// with an exposed one, and that a final size is not below the exposure
    /// end. Then commits the coverage, advances the exposure end and, for
    /// [`ExposedEnd::FinalSize`], records the exposed final size.
    ///
    /// # Errors
    ///
    /// [`ExposeUsageError`] for the checks above.
    ///
    /// # Panics
    ///
    /// If the coverage does not reach `usage_end`, which means the stored
    /// reservations no longer match the appended data.
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
        for final_size in [self.fixed_final_size, self.exposed_final_size]
            .into_iter()
            .flatten()
        {
            match end {
                ExposedEnd::Data => ensure!(
                    usage_end <= final_size,
                    expose_usage_error::BeyondFinalSizeSnafu {
                        usage_end,
                        final_size,
                    }
                ),
                ExposedEnd::FinalSize => ensure!(
                    usage_end == final_size,
                    expose_usage_error::FinalSizeMismatchSnafu {
                        final_size: usage_end,
                        established: final_size,
                    }
                ),
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
            let coverage = self
                .coverage
                .as_mut()
                .filter(|coverage| coverage.amount() >= newly_exposed)
                .expect("connection credit coverage reaches every appended byte");
            connection.commit(coverage.split_off(newly_exposed));
            self.exposure_end = usage_end;
        }
        if end == ExposedEnd::FinalSize {
            self.exposed_final_size = Some(usage_end);
        }
        Ok(newly_exposed)
    }
}
