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
//! the data, its reservation and the marker it was written with into the
//! buffer in one step, as one [`covered_bytes::CoveredBytes`] value whose
//! constructor has already checked that the reservation covers exactly the
//! data. The buffer groups the data waiting to be sent by the destination of
//! its marker ([`SendMarker`]) and decides the order within a stream; the
//! order between streams belongs to the send strategy.
use crate::send_options::SendOptions;
use crate::send_options::destination::{SendDestination, Unfulfilled};
use crate::stream_end::{BeyondFinalSizeError, FinalSizeChangeError};
use core::ops::Range;
use covered_bytes::CoveredBytes;
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
/// connection credit reservations that cover it, and the choice of what to
/// send next.
///
/// `B` is the type of the stored data, `R` that of the connection credit
/// reservations, which commit and release themselves, and `M` that of the
/// marker each piece of data was written with ([`SendMarker`]). One buffer
/// type may serve several data, reservation and marker types.
///
/// Implementations may organise and split their storage freely, provided
/// offsets keep their contents and splitting never duplicates the ownership
/// of a reservation.
///
/// # Selection and feedback
///
/// Data waiting to be sent is grouped by the current destination of its
/// marker ([`destinations`](Self::destinations)); within one destination the
/// buffer decides the order ([`next`](Self::next)). Selecting
/// ([`select`](Self::select)) hands out data and keeps it until it is
/// acknowledged: selection never deletes data that reliable delivery still
/// needs. Feedback is given by stream range:
///
/// - acknowledged data ([`on_acknowledged`](Self::on_acknowledged)) no longer
///   has to be kept and may be released; the written end does not move;
/// - lost data that is not acknowledged
///   ([`on_lost`](Self::on_lost)) waits to be sent again once its
///   destination fell back; committed credit is not returned and is not
///   committed again;
/// - data a reset abandoned never becomes eligible again, also when it is
///   reported lost later;
/// - an acknowledgement is never undone by a later loss of another
///   transmission of the same data.
pub trait StreamSendBuffer<B, R, M: SendMarker> {
    /// The written end: the cumulative end of all appended data.
    fn written_end(&self) -> VarInt;

    /// The exposure end (`exposure_end`): the end of the usage that may
    /// already be visible to the peer, or can no longer be prevented from
    /// becoming visible.
    ///
    /// The stream sender uses it to bound the final size of a reset.
    fn exposure_end(&self) -> VarInt;

    /// Appends `data` at the written end together with the reservation that
    /// covers it and its marker, and advances the written end by its length.
    ///
    /// The whole input is taken; there is no partial acceptance and no
    /// second admission. No credit is committed here. The data waits to be
    /// sent to the current destination of its marker.
    ///
    /// # Errors
    ///
    /// [`AppendError`] if the buffer takes no more data or the written end
    /// would pass [`VarInt::MAX`]; the error hands `data` back and nothing
    /// changes.
    fn append(&mut self, data: CoveredBytes<B, R, M>) -> Result<(), AppendError<B, R, M>>;

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
    /// [`ExposedContent::Data`]; a FIN or a reset frame uses the final size, with `content` set to
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

    /// The destinations that have data waiting to be sent, each once, by the
    /// current destination of the data's markers.
    fn destinations(&self) -> Vec<CurrentDestinationOf<M>>;

    /// The data that [`select`](Self::select) takes next for `destination`,
    /// if any waits for it; its marker gives the parameters of the send
    /// intent for that destination.
    fn next(&self, destination: &CurrentDestinationOf<M>) -> Option<NextSegment<'_, M>>;

    /// Takes at most `max_len` bytes from the start of
    /// [`next`](Self::next)`(destination)` for sending, and keeps them until
    /// they are acknowledged.
    ///
    /// Returns `None` if no data waits for `destination` or `max_len` is
    /// zero.
    fn select(
        &mut self,
        destination: &CurrentDestinationOf<M>,
        max_len: usize,
    ) -> Option<SelectedData<B>>;

    /// Applies an acknowledgement of the data in `range`: it no longer has to
    /// be kept, whether it was selected or waits to be sent again. Offsets
    /// not kept are ignored.
    ///
    /// Returns the destinations whose waiting data changed.
    fn on_acknowledged(&mut self, range: Range<VarInt>) -> Vec<CurrentDestinationOf<M>>;

    /// Applies the loss of the data in `range` that was selected and is not
    /// acknowledged: the destination of each such piece is told
    /// ([`StreamSendDestination::on_lost`]), and the piece waits for the
    /// destination it fell back to, or is reported as exhausted. Offsets not
    /// selected or not kept are ignored.
    ///
    /// [`StreamSendDestination::on_lost`]: crate::send_options::destination::StreamSendDestination::on_lost
    fn on_lost(&mut self, range: Range<VarInt>) -> DestinationChanges<CurrentDestinationOf<M>>;

    /// Applies that the send intent for `destination` was not fulfilled for
    /// `cause`: the destination of each piece waiting for it is told
    /// ([`SendDestination::on_unfulfilled`]), and the piece waits for the
    /// destination it fell back to, or is reported as exhausted.
    fn on_unfulfilled(
        &mut self,
        destination: &CurrentDestinationOf<M>,
        cause: Unfulfilled,
    ) -> DestinationChanges<CurrentDestinationOf<M>>;
}

/// What a send buffer reads from the marker of its data (`SendMarker`): the
/// destination the data goes to, which the buffer asks to fall back when
/// sending there fails.
pub trait SendMarker {
    /// The destination.
    type Destination: SendDestination;

    /// The destination of the data.
    fn destination(&self) -> &Self::Destination;

    /// The destination of the data, to let it fall back.
    fn destination_mut(&mut self) -> &mut Self::Destination;
}

/// The marker of a write is its send options.
impl<P, D: SendDestination> SendMarker for SendOptions<P, D> {
    type Destination = D;

    fn destination(&self) -> &D {
        SendOptions::destination(self)
    }

    fn destination_mut(&mut self) -> &mut D {
        SendOptions::destination_mut(self)
    }
}

/// The current destination of the data a marker `M` was written with.
pub type CurrentDestinationOf<M> = <<M as SendMarker>::Destination as SendDestination>::Current;

/// The data a send buffer sends next to one destination (`NextSegment`), as
/// [`StreamSendBuffer::next`] gives it.
#[derive(Debug)]
pub struct NextSegment<'a, M> {
    /// The stream offset of the first byte.
    pub offset: VarInt,
    /// The number of bytes a selection of any size could take at once.
    pub len: usize,
    /// The marker the data was written with.
    pub marker: &'a M,
}

/// Data selected for transmission and its position in the stream.
#[derive(Debug)]
pub struct SelectedData<B> {
    /// The stream offset of the first byte.
    pub offset: VarInt,
    /// The selected bytes.
    pub bytes: B,
}

/// What a loss or an unfulfilled intent changed (`DestinationChanges`):
/// the destinations whose waiting data changed, and the ranges left without
/// a destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationChanges<C> {
    /// The destinations whose waiting data changed, each once; the next
    /// segment of each may have changed, or none may be left.
    pub pending_changed: Vec<C>,
    /// The ranges whose destination has nothing left to fall back to, in
    /// stream order, adjacent ranges joined.
    pub exhausted: Vec<Range<VarInt>>,
}

impl<C> Default for DestinationChanges<C> {
    fn default() -> Self {
        Self {
            pending_changed: Vec::new(),
            exhausted: Vec::new(),
        }
    }
}

/// Failures of [`StreamSendBuffer::append`]; each hands the data back through
/// [`into_data`](Self::into_data).
#[derive(Debug, Snafu)]
#[snafu(module(append_error), visibility(pub(crate)))]
pub enum AppendError<B, R, M> {
    /// A reset was applied; the buffer takes no more data.
    #[snafu(display("a send buffer takes no data after a reset"))]
    AfterReset {
        /// The rejected data.
        data: CoveredBytes<B, R, M>,
    },
    /// A FIN or reset exposed the final size; the buffer takes no more data.
    #[snafu(display("a send buffer takes no data after the final size was exposed"))]
    AfterFinalSize {
        /// The exposed final size.
        source: FinalSizeEstablishedError,
        /// The rejected data.
        data: CoveredBytes<B, R, M>,
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
        data: CoveredBytes<B, R, M>,
    },
}

impl<B, R, M> AppendError<B, R, M> {
    /// The rejected data, unchanged.
    pub fn into_data(self) -> CoveredBytes<B, R, M> {
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
        source: ReliableSizeBeyondFinalSizeError,
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

/// A reset retention keeps a reliable size beyond its final size: data
/// beyond the end of the stream cannot be delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("reliable size {reliable_size} lies beyond the final size {final_size}"))]
pub struct ReliableSizeBeyondFinalSizeError {
    final_size: VarInt,
    reliable_size: VarInt,
}

impl ReliableSizeBeyondFinalSizeError {
    /// Checks that `reliable_size` is at most `final_size`.
    ///
    /// # Errors
    ///
    /// [`ReliableSizeBeyondFinalSizeError`] if `reliable_size` lies beyond
    /// `final_size`.
    pub fn check(final_size: VarInt, reliable_size: VarInt) -> Result<(), Self> {
        ensure!(
            reliable_size <= final_size,
            ReliableSizeBeyondFinalSizeSnafu {
                final_size,
                reliable_size,
            }
        );
        Ok(())
    }

    /// The final size.
    pub const fn final_size(self) -> VarInt {
        self.final_size
    }

    /// The rejected reliable size, beyond [`final_size`](Self::final_size).
    pub const fn reliable_size(self) -> VarInt {
        self.reliable_size
    }
}

/// The retention a reset leaves to a send buffer (`ResetRetention`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetRetention {
    /// The final size of the stream; coverage below it is retained.
    pub final_size: VarInt,
    /// The reliable size: data below it must still be delivered. It is zero
    /// for a reset that abandons all data.
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

#[cfg(test)]
mod tests;
