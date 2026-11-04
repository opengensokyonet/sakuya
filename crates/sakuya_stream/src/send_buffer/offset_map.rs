//! A send buffer keyed by stream offset ([`OffsetMapStreamSendBuffer`]).
use super::covered_bytes::CoveredBytes;
use super::visibility::{CoverError, VisibilitySettlement};
use super::{
    AppendError, ApplyResetError, ExposeUsageError, ExposedContent, FinalSizeBeyondWrittenEndError,
    ResetRetention, Selection, SelectionConstraints, StreamSendBuffer, TransmissionReceipt,
    append_error, apply_reset_error,
};
use crate::connection_send_credit::ConnectionCreditReservation;
use bytes::Bytes;
use sakuya_wire::frame::reset_stream_at::ReliableSizeError;
use sakuya_wire::var_int::VarInt;
use snafu::{IntoError, ResultExt};
use std::collections::BTreeMap;

/// A send buffer that keeps each appended [`Bytes`] as it arrived, keyed by
/// its stream offset.
///
/// Appending stores the handle without copying the payload; a reset shortens
/// the retained data by slicing, also without copying. Connection credit
/// coverage is kept in an embedded [`VisibilitySettlement`].
///
/// Selection and feedback take inputs that have no values yet.
#[derive(Debug)]
pub struct OffsetMapStreamSendBuffer<R> {
    written_end: VarInt,
    retained: BTreeMap<VarInt, Bytes>,
    visibility: VisibilitySettlement<R>,
    input: Input,
}

/// Whether the buffer still takes data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Input {
    /// Appends are accepted.
    #[default]
    Open,
    /// A reset was applied; the retention is the one applied last.
    Reset(ResetRetention),
}

impl<R> Default for OffsetMapStreamSendBuffer<R> {
    fn default() -> Self {
        Self {
            written_end: VarInt::ZERO,
            retained: BTreeMap::new(),
            visibility: VisibilitySettlement::default(),
            input: Input::Open,
        }
    }
}

impl<R: ConnectionCreditReservation> OffsetMapStreamSendBuffer<R> {
    /// Creates an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The retained data in offset order, as `(offset, bytes)`.
    pub fn retained(&self) -> impl Iterator<Item = (VarInt, &Bytes)> {
        self.retained.iter().map(|(&offset, bytes)| (offset, bytes))
    }

    /// The visibility settlement: exposure end, final size and uncommitted
    /// coverage.
    pub fn visibility(&self) -> &VisibilitySettlement<R> {
        &self.visibility
    }

    /// The reset retention applied last, if any.
    pub fn retention(&self) -> Option<ResetRetention> {
        match self.input {
            Input::Open => None,
            Input::Reset(retention) => Some(retention),
        }
    }
}

impl<R: ConnectionCreditReservation> StreamSendBuffer for OffsetMapStreamSendBuffer<R> {
    type Reservation = R;

    fn written_end(&self) -> VarInt {
        self.written_end
    }

    fn exposure_end(&self) -> VarInt {
        self.visibility.exposure_end()
    }

    fn append(&mut self, data: CoveredBytes<R>) -> Result<(), AppendError<R>> {
        if let Input::Reset(_) = self.input {
            return append_error::AfterResetSnafu { data }.fail();
        }
        let offset = self.written_end;
        let Some(end) = offset.checked_add(data.len()) else {
            return append_error::WrittenEndOverflowSnafu {
                written_end: offset,
                data,
            }
            .fail();
        };
        let bytes = match self.visibility.cover(offset, data) {
            Ok(bytes) => bytes,
            Err(CoverError::FinalSizeEstablished { source, data }) => {
                // Only `apply_reset` fixes a final size, and it closes input
                // above, so this one was exposed by a FIN.
                return Err(append_error::AfterFinalSizeSnafu { data }.into_error(source));
            }
            Err(CoverError::NotContiguous { data, .. } | CoverError::EndOverflow { data, .. }) => {
                // invariant: while input is open the coverage starts at the
                // exposure end and ends at the written end, so it continues at
                // `offset` and ends at `end`, a `VarInt`.
                unreachable!(
                    "coverage of an open send buffer ends at its written end; rejected {} bytes",
                    data.len()
                )
            }
        };
        self.written_end = end;
        if !bytes.is_empty() {
            self.retained.insert(offset, bytes);
        }
        Ok(())
    }

    fn apply_reset(&mut self, retention: ResetRetention) -> Result<(), ApplyResetError> {
        let ResetRetention {
            final_size,
            reliable_size,
        } = retention;
        ReliableSizeError::check(final_size, reliable_size)
            .context(apply_reset_error::ReliableSizeBeyondFinalSizeSnafu)?;
        FinalSizeBeyondWrittenEndError::check(final_size, self.written_end)
            .context(apply_reset_error::FinalSizeBeyondWrittenEndSnafu)?;
        self.visibility
            .fix_final_size(final_size)
            .context(apply_reset_error::FixFinalSizeSnafu)?;

        // Data at and beyond the reliable size loses its eligibility for
        // sending; the entry straddling the reliable size is sliced.
        drop(self.retained.split_off(&reliable_size));
        if let Some((&offset, bytes)) = self.retained.range_mut(..reliable_size).next_back() {
            let kept = reliable_size.get() - offset.get();
            if let Ok(kept) = usize::try_from(kept)
                && kept < bytes.len()
            {
                bytes.truncate(kept);
            }
        }
        self.input = Input::Reset(retention);
        Ok(())
    }

    fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
        content: ExposedContent,
    ) -> Result<VarInt, ExposeUsageError> {
        self.visibility
            .expose_usage_through(usage_end, content, self.written_end)
    }

    fn select(&mut self, constraints: SelectionConstraints) -> Selection {
        match constraints {}
    }

    fn on_acknowledged(&mut self, receipt: TransmissionReceipt) {
        match receipt {}
    }

    fn on_lost(&mut self, receipt: TransmissionReceipt) {
        match receipt {}
    }
}
