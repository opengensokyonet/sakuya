//! The send buffer contract ([`StreamSendBuffer`]), the per-stream visibility
//! settlement it uses ([`visibility::VisibilitySettlement`]) and an
//! implementation keyed by stream offset ([`offset_map::OffsetMapStreamSendBuffer`]).
//!
//! A send buffer stores the data a stream sender has accepted, owns the
//! connection credit reservations that cover it, and maintains the written
//! end (`written_end`): the cumulative end of everything appended since the
//! start of the stream. The written end never moves back, also when
//! acknowledged data is released.
//!
//! The buffer is append-only: callers do not choose offsets. Appending moves
//! the data and its reservation into the buffer in one step, as one
//! [`covered_bytes::CoveredBytes`] value whose constructor has already
//! checked that the reservation covers exactly the data.
use crate::connection_send_credit::ConnectionCreditReservation;
use crate::stream_end::{BeyondFinalSizeError, FinalSizeChangeError};
use bytes::Bytes;
use covered_bytes::CoveredBytes;
use sakuya_wire::reset_stream_at::ReliableSizeError;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};
use visibility::{
    FinalSizeBelowExposureError, FinalSizeEstablishedError, FixFinalSizeError,
    UsageBeyondCoverageError,
};

pub mod covered_bytes;
pub mod offset_map;
pub mod visibility;

/// Storage of the data a stream sender has accepted, together with the
/// connection credit reservations that cover it.
///
/// Implementations may organise and split their storage freely, provided
/// offsets keep their contents and splitting never duplicates the ownership
/// of a reservation.
///
/// [`select`](Self::select), [`on_acknowledged`](Self::on_acknowledged) and
/// [`on_lost`](Self::on_lost) have no callable inputs yet. This interface is
/// provisional.
pub trait StreamSendBuffer {
    /// The connection credit reservation type the buffer takes with the data
    /// it covers; it commits and releases itself.
    type Reservation: ConnectionCreditReservation;

    /// The written end: the cumulative end of all appended data.
    fn written_end(&self) -> VarInt;

    /// The exposure end (`exposure_end`): the end of the usage that may
    /// already be visible to the peer, or can no longer be prevented from
    /// becoming visible.
    ///
    /// The stream sender uses it to bound the final size of a reset.
    fn exposure_end(&self) -> VarInt;

    /// Appends `data` at the written end together with the reservation that
    /// covers it, and advances the written end by its length.
    ///
    /// The whole input is taken; there is no partial acceptance and no
    /// second admission. No credit is committed here.
    ///
    /// # Errors
    ///
    /// [`AppendError`] if the buffer takes no more data or the written end
    /// would pass [`VarInt::MAX`]; the error hands `data` back and nothing
    /// changes.
    fn append(
        &mut self,
        data: CoveredBytes<Self::Reservation>,
    ) -> Result<(), AppendError<Self::Reservation>>;

    /// Applies a reset target.
    ///
    /// Closes future appends; keeps the data below
    /// [`ResetRetention::reliable_size`] that still has to be delivered and
    /// makes the rest ineligible for sending; keeps the uncommitted coverage
    /// below [`ResetRetention::final_size`] and releases only the
    /// reservations beyond it, which can never be exposed. Committed credit
    /// is not returned and the written end does not move. A later call may
    /// lower the reliable size with the same final size; repeating a target
    /// releases nothing twice.
    ///
    /// # Errors
    ///
    /// [`ApplyResetError`] if the reliable size exceeds the final size, the
    /// final size lies beyond the written end or below the exposure end, or
    /// it differs from a final size established before; nothing changes then.
    fn apply_reset(&mut self, retention: ResetRetention) -> Result<(), ApplyResetError>;

    /// Settles the first exposure of usage up to `usage_end` at an
    /// irrevocable hand-over boundary: commits the coverage between the
    /// current exposure end and `usage_end` and advances the exposure end
    /// monotonically.
    ///
    /// Data uses the end of the range it carries, with `content` set to
    /// [`ExposedContent::Data`]; a FIN, a `RESET_STREAM` or a
    /// `RESET_STREAM_AT` uses the final size, with `content` set to
    /// [`ExposedContent::FinalSize`], even when no data is left to send. Each
    /// reservation that covers newly exposed usage commits itself. Returns the
    /// newly committed amount, `max(E, usage_end) − E`; usage at or below the
    /// exposure end commits nothing again.
    ///
    /// # Errors
    ///
    /// [`ExposeUsageError`] if the exposure is inconsistent with the written
    /// end, an established final size or the stored coverage; nothing
    /// changes then.
    fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
        content: ExposedContent,
    ) -> Result<VarInt, ExposeUsageError>;

    /// Selects data to hand to the link layer within `constraints`.
    ///
    /// Selection must not delete data that reliable delivery still needs.
    /// [`SelectionConstraints`] has no values yet, so this method cannot be
    /// called. This interface is provisional.
    fn select(&mut self, constraints: SelectionConstraints) -> Selection;

    /// Applies an acknowledgement of the data a transmission carried.
    ///
    /// Acknowledged data no longer has to be retained; the written end does
    /// not move. [`TransmissionReceipt`] has no values yet, so this method
    /// cannot be called. This interface is provisional.
    fn on_acknowledged(&mut self, receipt: TransmissionReceipt);

    /// Applies the loss of the data a transmission carried.
    ///
    /// Lost, unacknowledged data becomes eligible for sending again;
    /// committed credit is not returned and is not committed again.
    /// [`TransmissionReceipt`] has no values yet, so this method cannot be
    /// called. This interface is provisional.
    fn on_lost(&mut self, receipt: TransmissionReceipt);
}

/// Failures of [`StreamSendBuffer::append`]; each hands the data back through
/// [`into_data`](Self::into_data).
#[derive(Debug, Snafu)]
#[snafu(module(append_error), visibility(pub(crate)))]
pub enum AppendError<R> {
    /// A reset was applied; the buffer takes no more data.
    #[snafu(display("a send buffer takes no data after a reset"))]
    AfterReset {
        /// The rejected data.
        data: CoveredBytes<R>,
    },
    /// A FIN or reset exposed the final size; the buffer takes no more data.
    #[snafu(display("a send buffer takes no data after the final size was exposed"))]
    AfterFinalSize {
        /// The exposed final size.
        source: FinalSizeEstablishedError,
        /// The rejected data.
        data: CoveredBytes<R>,
    },
    /// The written end would pass [`VarInt::MAX`].
    #[snafu(display(
        "{} bytes at the written end {written_end} would pass the largest stream offset",
        data.len()
    ))]
    WrittenEndOverflow {
        /// The written end.
        written_end: VarInt,
        /// The rejected data.
        data: CoveredBytes<R>,
    },
}

impl<R> AppendError<R> {
    /// The rejected data, unchanged.
    pub fn into_data(self) -> CoveredBytes<R> {
        match self {
            Self::AfterReset { data }
            | Self::AfterFinalSize { data, .. }
            | Self::WrittenEndOverflow { data, .. } => data,
        }
    }
}

/// Failures of [`StreamSendBuffer::apply_reset`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(apply_reset_error), visibility(pub(crate)))]
pub enum ApplyResetError {
    /// The reliable size exceeds the final size.
    #[snafu(display("the reset retention keeps a reliable size beyond its final size"))]
    ReliableSizeBeyondFinalSize {
        /// The requested reliable size and final size.
        source: ReliableSizeError,
    },
    /// The final size lies beyond the written end.
    #[snafu(display("the reset retention keeps a final size beyond the written end"))]
    FinalSizeBeyondWrittenEnd {
        /// The requested final size and the written end.
        source: FinalSizeBeyondWrittenEndError,
    },
    /// The final size cannot be fixed.
    #[snafu(display("cannot fix the final size"))]
    FixFinalSize {
        /// Why the final size was rejected.
        source: FixFinalSizeError,
    },
}

/// A final size lies beyond the written end: a stream cannot end after data
/// that was never handed over.
///
/// The stream sender checks it for a reset it is asked for, and a send
/// buffer when it applies a reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("final size {final_size} lies beyond the written end {written_end}"))]
pub struct FinalSizeBeyondWrittenEndError {
    final_size: VarInt,
    written_end: VarInt,
}

impl FinalSizeBeyondWrittenEndError {
    /// Checks that `final_size` is at most `written_end`.
    ///
    /// # Errors
    ///
    /// [`FinalSizeBeyondWrittenEndError`] if `final_size` lies beyond
    /// `written_end`.
    pub fn check(final_size: VarInt, written_end: VarInt) -> Result<(), Self> {
        ensure!(
            final_size <= written_end,
            FinalSizeBeyondWrittenEndSnafu {
                final_size,
                written_end,
            }
        );
        Ok(())
    }

    /// The rejected final size, beyond [`written_end`](Self::written_end).
    pub const fn final_size(self) -> VarInt {
        self.final_size
    }

    /// The written end.
    pub const fn written_end(self) -> VarInt {
        self.written_end
    }
}

/// The retention a reset leaves to a send buffer (`ResetRetention`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetRetention {
    /// The final size of the stream; coverage below it is retained.
    pub final_size: VarInt,
    /// The reliable size: data below it must still be delivered.
    pub reliable_size: VarInt,
}

/// What an exposure carries besides usage (`ExposedContent`): stream data,
/// or the announcement of the final size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExposedContent {
    /// Stream data whose range ends at the usage end; no final size.
    Data,
    /// The final size, equal to the usage end. A FIN and both reset frames
    /// announce it, and the buffer does not tell them apart.
    FinalSize,
}

impl ExposedContent {
    /// Whether the exposure announces a final size.
    pub(crate) const fn announces_final_size(self) -> bool {
        matches!(self, Self::FinalSize)
    }
}

/// Failures of [`StreamSendBuffer::expose_usage_through`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(expose_usage_error), visibility(pub(crate)))]
pub enum ExposeUsageError {
    /// The usage end lies beyond the written end.
    #[snafu(display("cannot expose usage that was not written"))]
    BeyondWrittenEnd {
        /// The rejected usage end and the written end.
        source: UsageBeyondWrittenEndError,
    },
    /// The usage end lies beyond the final size already fixed or exposed.
    #[snafu(display("data exposure passes the final size"))]
    BeyondFinalSize {
        /// The final size and the rejected usage end.
        source: BeyondFinalSizeError,
    },
    /// A final size differs from the one already fixed or exposed.
    #[snafu(display("exposure changes the final size"))]
    FinalSizeMismatch {
        /// The final size already fixed or exposed and the rejected one.
        source: FinalSizeChangeError,
    },
    /// A final size lies below the exposure end.
    #[snafu(display("cannot expose a final size below the exposed usage"))]
    FinalSizeBelowExposure {
        /// The rejected final size and the exposure end.
        source: FinalSizeBelowExposureError,
    },
    /// The stored coverage does not reach the usage end.
    #[snafu(display("cannot expose usage without stored coverage"))]
    BeyondCoverage {
        /// The rejected usage end and the end of the stored coverage.
        source: UsageBeyondCoverageError,
    },
}

/// A usage end lies beyond the written end: usage that was never handed
/// over cannot be exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("usage end {usage_end} lies beyond the written end {written_end}"))]
pub struct UsageBeyondWrittenEndError {
    usage_end: VarInt,
    written_end: VarInt,
}

impl UsageBeyondWrittenEndError {
    /// Checks that `usage_end` is at most `written_end`.
    ///
    /// # Errors
    ///
    /// [`UsageBeyondWrittenEndError`] if `usage_end` lies beyond
    /// `written_end`.
    pub fn check(usage_end: VarInt, written_end: VarInt) -> Result<(), Self> {
        ensure!(
            usage_end <= written_end,
            UsageBeyondWrittenEndSnafu {
                usage_end,
                written_end,
            }
        );
        Ok(())
    }

    /// The rejected usage end, beyond [`written_end`](Self::written_end).
    pub const fn usage_end(self) -> VarInt {
        self.usage_end
    }

    /// The written end.
    pub const fn written_end(self) -> VarInt {
        self.written_end
    }
}

/// The constraints a send scheduler passes to [`StreamSendBuffer::select`].
///
/// The type has no values yet, so no selection can be requested. This
/// interface is provisional.
#[derive(Debug)]
pub enum SelectionConstraints {}

/// The result of [`StreamSendBuffer::select`].
///
/// This interface is provisional.
#[derive(Debug)]
pub enum Selection {
    /// Data was selected.
    Selected(SelectedData),
    /// No data is eligible within the constraints.
    NoCandidate,
}

/// Data selected for transmission and its position in the stream.
///
/// This interface is provisional.
#[derive(Debug)]
pub struct SelectedData {
    /// The stream offset of the first byte.
    pub offset: VarInt,
    /// The selected bytes.
    pub bytes: Bytes,
}

/// The record of which data one transmission carried, passed back with
/// acknowledgement and loss feedback.
///
/// The type has no values yet. This interface is provisional.
#[derive(Debug)]
pub enum TransmissionReceipt {}

#[cfg(test)]
mod tests;
