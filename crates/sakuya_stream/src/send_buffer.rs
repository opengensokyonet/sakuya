//! The send buffer contract ([`SendBuffer`]), the per-stream visibility
//! settlement it uses ([`VisibilitySettlement`]) and a basic implementation
//! ([`BasicSendBuffer`]).
//!
//! A send buffer stores the data a stream sender has accepted, owns the
//! connection credit reservations that cover it, and maintains the written
//! end (`written_end`): the cumulative end of everything appended since the
//! start of the stream. The written end never moves back, also when
//! acknowledged data is released.
//!
//! The buffer is append-only: callers do not choose offsets. Appending moves
//! the data and its reservation into the buffer in one step and cannot fail;
//! anything that can fail is checked before the stream sender consumes its
//! caller's input.
//!
//! Status: append-only storage and the ownership of `written_end` and of the
//! data-to-reservation correspondence are confirmed (`send-side.md`,
//! "只追加与状态归属（已确认）"). The method set follows the tentative
//! "保留与暴露接口（暂定）"; selection and feedback keep a minimal shape until
//! the send design settles them.
use crate::connection_send_credit::{ConnectionCreditReservation, ConnectionSendFlowController};
use bytes::Bytes;
use sakuya_wire::var_int::VarInt;
use snafu::Snafu;

mod basic;
mod visibility;

pub use basic::BasicSendBuffer;
pub use visibility::VisibilitySettlement;

/// Storage of the data a stream sender has accepted, together with the
/// connection credit reservations that cover it.
///
/// Implementations may organise and split their storage freely, provided
/// offsets keep their contents and splitting never duplicates the ownership
/// of a reservation.
///
/// Status: tentative interface (`send-side.md`, "保留与暴露接口（暂定）").
/// [`select`](Self::select), [`on_acknowledged`](Self::on_acknowledged) and
/// [`on_lost`](Self::on_lost) only fix a shape until the send design
/// specifies selection and feedback.
pub trait SendBuffer {
    /// The written end: the cumulative end of all appended data.
    fn written_end(&self) -> VarInt;

    /// The exposure end (`exposure_end`): the end of the usage that may
    /// already be visible to the peer, or can no longer be prevented from
    /// becoming visible.
    ///
    /// Status: an addition to the tentative interface; the stream sender needs
    /// it to bound the final size of a reset, and the buffer is the proposed
    /// owner of the per-stream visibility settlement
    /// (`send-accounting.md`, "每流可见性结算职责（建议待确认）").
    fn exposure_end(&self) -> VarInt;

    /// Appends `bytes` at the written end together with the reservation that
    /// covers them, and advances the written end by their length.
    ///
    /// The whole input is taken; there is no partial acceptance and no
    /// second admission. No credit is committed here.
    ///
    /// # Panics
    ///
    /// Implementations panic if the reservation's amount differs from the
    /// length of `bytes`, or if a reset was applied before.
    fn append(&mut self, bytes: Bytes, connection_credit_reservation: ConnectionCreditReservation);

    /// Applies a reset target that the stream sender has already validated.
    ///
    /// Closes future appends; keeps the data below
    /// [`ResetRetention::reliable_size`] that still has to be delivered and
    /// makes the rest ineligible for sending; keeps the uncommitted coverage
    /// below [`ResetRetention::final_size`] and releases only the
    /// reservations beyond it, which can never be exposed. Committed credit
    /// is not returned and the written end does not move. A later call may
    /// lower the reliable size with the same final size; repeating a target
    /// releases nothing twice.
    fn apply_reset(&mut self, retention: ResetRetention);

    /// Settles the first exposure of usage up to `usage_end` at an
    /// irrevocable hand-over boundary: commits the coverage between the
    /// current exposure end and `usage_end` and advances the exposure end
    /// monotonically.
    ///
    /// Data uses the end of the range it carries; a FIN or a reset uses the
    /// final size, with `end` set to [`ExposedEnd::FinalSize`]. Returns the
    /// newly committed amount, `max(E, usage_end) − E`; usage at or below the
    /// exposure end commits nothing again.
    ///
    /// Status: capability placeholder (`send-side.md`); where the send
    /// mechanism calls it is open. The settlement follows the candidate steps
    /// of `send-accounting.md`, "统一 STREAM、FIN 和 RESET 的额度影响（候选）".
    ///
    /// # Errors
    ///
    /// [`ExposeUsageError`] if the exposure is inconsistent with the written
    /// end or an established final size; nothing changes then.
    fn expose_usage_through(
        &mut self,
        usage_end: VarInt,
        end: ExposedEnd,
        connection: &mut ConnectionSendFlowController,
    ) -> Result<VarInt, ExposeUsageError>;

    /// Selects data to hand to the link layer within `constraints`.
    ///
    /// Status: pending the send design. Selection must not delete data that
    /// reliable delivery still needs.
    fn select(&mut self, constraints: SelectionConstraints) -> Selection;

    /// Applies an acknowledgement of the data a transmission carried.
    ///
    /// Status: pending the send design. Acknowledged data no longer has to be
    /// retained; the written end does not move.
    fn on_acknowledged(&mut self, receipt: TransmissionReceipt);

    /// Applies the loss of the data a transmission carried.
    ///
    /// Status: pending the send design. Lost, unacknowledged data becomes a
    /// candidate again; committed credit is not returned and is not committed
    /// again.
    fn on_lost(&mut self, receipt: TransmissionReceipt);
}

/// The retention a reset leaves to a send buffer (`ResetRetention`).
///
/// Status: tentative (`send-side.md`, "保留与暴露接口（暂定）").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetRetention {
    /// The final size of the stream; coverage below it is retained.
    pub final_size: VarInt,
    /// The reliable size: data below it must still be delivered.
    pub reliable_size: VarInt,
}

/// What an exposure announces besides usage (`ExposedEnd`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExposedEnd {
    /// Stream data whose range ends at the usage end; no final size.
    Data,
    /// A final size equal to the usage end: a FIN, a `RESET_STREAM` or a
    /// `RESET_STREAM_AT`.
    FinalSize,
}

/// Failures of [`SendBuffer::expose_usage_through`] and of the stream
/// sender's exposure entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(expose_usage_error), visibility(pub(crate)))]
pub enum ExposeUsageError {
    /// The usage end lies beyond the written end.
    #[snafu(display("usage end {usage_end} lies beyond the written end {written_end}"))]
    BeyondWrittenEnd {
        /// The rejected usage end.
        usage_end: VarInt,
        /// The written end.
        written_end: VarInt,
    },
    /// The usage end lies beyond the final size already fixed or exposed.
    #[snafu(display("usage end {usage_end} lies beyond the final size {final_size}"))]
    BeyondFinalSize {
        /// The rejected usage end.
        usage_end: VarInt,
        /// The final size.
        final_size: VarInt,
    },
    /// A final size differs from the one already fixed or exposed.
    #[snafu(display("final size {final_size} differs from the established {established}"))]
    FinalSizeMismatch {
        /// The rejected final size.
        final_size: VarInt,
        /// The final size already fixed or exposed.
        established: VarInt,
    },
    /// A final size lies below the exposure end.
    #[snafu(display("final size {final_size} lies below the exposure end {exposure_end}"))]
    FinalSizeBelowExposure {
        /// The rejected final size.
        final_size: VarInt,
        /// The exposure end.
        exposure_end: VarInt,
    },
    /// A final size is exposed while the stream has no fixed final size.
    #[snafu(display("final size {final_size} exposed before the stream ended"))]
    FinalSizeNotFixed {
        /// The rejected final size.
        final_size: VarInt,
    },
}

/// The constraints a send scheduler passes to [`SendBuffer::select`].
///
/// Status: pending the send design. The type has no values yet, so no
/// selection can be requested.
#[derive(Debug)]
pub enum SelectionConstraints {}

/// The result of [`SendBuffer::select`].
///
/// Status: pending the send design.
#[derive(Debug)]
pub enum Selection {
    /// Data was selected.
    Selected(SelectedData),
    /// No data is eligible within the constraints.
    NoCandidate,
}

/// Data selected for transmission and its position in the stream.
///
/// Status: pending the send design.
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
/// Status: pending the send design. The type has no values yet.
#[derive(Debug)]
pub enum TransmissionReceipt {}

#[cfg(test)]
mod tests;
