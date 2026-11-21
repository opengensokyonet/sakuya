//! A send buffer keyed by stream offset ([`OffsetMapStreamSendBuffer`]).
use super::covered_bytes::CoveredBytes;
use super::visibility::{CoverError, VisibilitySettlement};
use super::{
    AppendError, ApplyResetError, CurrentDestinationOf, DestinationChanges, ExposeUsageError,
    ExposedContent, FinalSizeBeyondWrittenEndError, NextSegment, ReliableSizeBeyondFinalSizeError,
    ResetRetention, SelectedData, SendMarker, StreamSendBuffer, append_error, apply_reset_error,
};
use crate::connection_send_credit::ConnectionCreditReservation;
use crate::send_options::SendOptions;
use crate::send_options::destination::{DestinationFallback, StreamSendDestination, Unfulfilled};
use crate::send_options::urgency::{SendUrgency, Urgency};
use bytes::Buf;
use core::fmt;
use core::ops::Range;
use nitori_io::SplitTo;
use sakuya_wire_v1::var_int::VarInt;
use smallvec::SmallVec;
use snafu::{IntoError, ResultExt};
use std::collections::{BTreeMap, BTreeSet};

/// A send buffer that keeps each appended piece of data as it arrived, keyed
/// by its stream offset, together with the marker it was written with.
///
/// Appending stores the data without copying the payload; selecting,
/// feedback and a reset split it with [`SplitTo`], also without copying for
/// `Bytes`. Connection credit coverage is kept in an embedded
/// [`VisibilitySettlement`].
///
/// Each piece waits to be sent, is selected and not yet acknowledged, or has
/// no destination left; acknowledged data and data a reset abandoned are
/// gone. The pieces waiting are grouped by the current destination of their
/// markers, and within a destination ordered by urgency, then by offset.
///
/// The selection and feedback of [`StreamSendBuffer`] are implemented for
/// markers that are [`SendOptions`] whose parameters give an urgency
/// ([`SendUrgency`]) and whose destination is a [`StreamSendDestination`].
/// The data's [`SplitTo`] cuts at the same lengths as its
/// [`Buf::remaining`] counts.
pub struct OffsetMapStreamSendBuffer<B, R, M: SendMarker> {
    written_end: VarInt,
    /// The data kept, by offset: not acknowledged and not abandoned by a
    /// reset.
    pieces: BTreeMap<VarInt, Piece<B, M>>,
    /// The pieces waiting to be sent, by destination; no group is empty.
    waiting: Vec<WaitingGroup<CurrentDestinationOf<M>>>,
    visibility: VisibilitySettlement<R>,
    input: Input,
}

/// A piece of data and the marker it was written with.
#[derive(Debug)]
struct Piece<B, M> {
    bytes: B,
    marker: M,
    state: PieceState,
}

/// Where a piece is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PieceState {
    /// It waits to be sent to the current destination of its marker.
    Waiting,
    /// It was selected and is neither acknowledged nor lost.
    Selected,
    /// It was lost or not sent, and its destination has nothing left to fall
    /// back to.
    Exhausted,
}

/// The pieces waiting for one destination, as (urgency, offset).
#[derive(Debug)]
struct WaitingGroup<C> {
    destination: C,
    pieces: BTreeSet<(Urgency, VarInt)>,
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

impl<B, R, M: SendMarker> Default for OffsetMapStreamSendBuffer<B, R, M> {
    fn default() -> Self {
        Self {
            written_end: VarInt::ZERO,
            pieces: BTreeMap::new(),
            waiting: Vec::new(),
            visibility: VisibilitySettlement::default(),
            input: Input::Open,
        }
    }
}

impl<B, R, M> fmt::Debug for OffsetMapStreamSendBuffer<B, R, M>
where
    B: fmt::Debug,
    R: fmt::Debug,
    M: SendMarker + fmt::Debug,
    CurrentDestinationOf<M>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OffsetMapStreamSendBuffer")
            .field("written_end", &self.written_end)
            .field("pieces", &self.pieces)
            .field("waiting", &self.waiting)
            .field("visibility", &self.visibility)
            .field("input", &self.input)
            .finish()
    }
}

impl<B, R: ConnectionCreditReservation, M: SendMarker> OffsetMapStreamSendBuffer<B, R, M> {
    /// Creates an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The data kept in offset order, as `(offset, data)`: what is not
    /// acknowledged and not abandoned by a reset, whether it waits, was
    /// selected or has no destination left.
    pub fn retained(&self) -> impl Iterator<Item = (VarInt, &B)> {
        self.pieces
            .iter()
            .map(|(&offset, piece)| (offset, &piece.bytes))
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

/// The end of `len` bytes at `offset` within the buffer.
fn end_of(offset: VarInt, len: usize) -> VarInt {
    // invariant: every piece lies below the written end, a `VarInt`.
    VarInt::try_from(offset.get().saturating_add(len as u64)).unwrap_or(VarInt::MAX)
}

/// `end − start` for two offsets within one piece, as the `usize` that
/// splitting the piece takes.
fn len_between(start: VarInt, end: VarInt) -> usize {
    // invariant: both lie within one piece, whose length is a `usize`.
    usize::try_from(end.get().saturating_sub(start.get())).unwrap_or(usize::MAX)
}

/// Adds the piece at `offset` with `urgency` to the group of `destination`.
fn enqueue<C: Eq>(
    waiting: &mut Vec<WaitingGroup<C>>,
    destination: C,
    urgency: Urgency,
    offset: VarInt,
) {
    let key = (urgency, offset);
    match waiting
        .iter_mut()
        .find(|group| group.destination == destination)
    {
        Some(group) => {
            group.pieces.insert(key);
        }
        None => waiting.push(WaitingGroup {
            destination,
            pieces: BTreeSet::from([key]),
        }),
    }
}

/// Removes the piece at `offset` with `urgency` from the group of
/// `destination`, and the group if it is left empty.
fn unqueue<C: Eq>(
    waiting: &mut Vec<WaitingGroup<C>>,
    destination: &C,
    urgency: Urgency,
    offset: VarInt,
) {
    let Some(index) = waiting
        .iter()
        .position(|group| group.destination == *destination)
    else {
        return;
    };
    let group = &mut waiting[index];
    group.pieces.remove(&(urgency, offset));
    if group.pieces.is_empty() {
        waiting.remove(index);
    }
}

/// Records `destination` among the changed ones, once.
fn note_changed<C: Eq>(changed: &mut Vec<C>, destination: C) {
    if !changed.contains(&destination) {
        changed.push(destination);
    }
}

/// Sorts `ranges` by start and joins adjacent ones.
fn join_ranges(mut ranges: Vec<Range<VarInt>>) -> Vec<Range<VarInt>> {
    ranges.sort_by_key(|range| range.start);
    let mut joined: Vec<Range<VarInt>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match joined.last_mut() {
            Some(last) if last.end == range.start => last.end = range.end,
            _ => joined.push(range),
        }
    }
    joined
}

impl<B, R, P, D> OffsetMapStreamSendBuffer<B, R, SendOptions<P, D>>
where
    B: Buf + SplitTo + Clone,
    R: ConnectionCreditReservation,
    P: SendUrgency + Clone,
    D: StreamSendDestination + Clone,
    D::Current: Clone + Eq,
{
    /// Makes `at` a piece boundary if a piece whose state `split` accepts
    /// straddles it; the tail keeps the state and a copy of the marker.
    fn split_at(&mut self, at: VarInt, split: impl Fn(PieceState) -> bool) {
        let Some((&start, piece)) = self.pieces.range_mut(..at).next_back() else {
            return;
        };
        if end_of(start, piece.bytes.remaining()) <= at || !split(piece.state) {
            return;
        }
        let head = match piece.bytes.split_to(len_between(start, at)) {
            Ok(head) => head,
            // invariant: `at` lies inside the piece.
            Err(error) => unreachable!("cannot split a piece at its interior: {error}"),
        };
        let tail = Piece {
            bytes: core::mem::replace(&mut piece.bytes, head),
            marker: piece.marker.clone(),
            state: piece.state,
        };
        if tail.state == PieceState::Waiting {
            enqueue(
                &mut self.waiting,
                tail.marker.destination().current(),
                tail.marker.parameters().urgency(),
                at,
            );
        }
        self.pieces.insert(at, tail);
    }

    /// The offsets of the pieces that start in `range`: usually a few,
    /// inline.
    fn offsets_in(&self, range: &Range<VarInt>) -> SmallVec<[VarInt; 8]> {
        self.pieces
            .range(range.clone())
            .map(|(&offset, _)| offset)
            .collect()
    }

    /// Drops the pieces from `offset` on.
    fn drop_from(&mut self, offset: VarInt) {
        for (start, piece) in self.pieces.split_off(&offset) {
            if piece.state == PieceState::Waiting {
                unqueue(
                    &mut self.waiting,
                    &piece.marker.destination().current(),
                    piece.marker.parameters().urgency(),
                    start,
                );
            }
        }
    }

    /// The piece at `offset` fell back as `fallback`; it now waits or is
    /// exhausted.
    fn apply_fallback(
        &mut self,
        offset: VarInt,
        fallback: DestinationFallback,
        changes: &mut DestinationChanges<D::Current>,
    ) {
        let Some(piece) = self.pieces.get_mut(&offset) else {
            return;
        };
        match fallback {
            DestinationFallback::Degraded => {
                piece.state = PieceState::Waiting;
                let destination = piece.marker.destination().current();
                enqueue(
                    &mut self.waiting,
                    destination.clone(),
                    piece.marker.parameters().urgency(),
                    offset,
                );
                note_changed(&mut changes.pending_changed, destination);
            }
            DestinationFallback::Exhausted => {
                piece.state = PieceState::Exhausted;
                changes
                    .exhausted
                    .push(offset..end_of(offset, piece.bytes.remaining()));
            }
        }
    }
}

impl<B, R, P, D> StreamSendBuffer<B, R, SendOptions<P, D>>
    for OffsetMapStreamSendBuffer<B, R, SendOptions<P, D>>
where
    B: Buf + SplitTo + Clone,
    R: ConnectionCreditReservation,
    P: SendUrgency + Clone,
    D: StreamSendDestination + Clone,
    D::Current: Clone + Eq,
{
    fn written_end(&self) -> VarInt {
        self.written_end
    }

    fn exposure_end(&self) -> VarInt {
        self.visibility.exposure_end()
    }

    fn append(
        &mut self,
        data: CoveredBytes<B, R, SendOptions<P, D>>,
    ) -> Result<(), AppendError<B, R, SendOptions<P, D>>> {
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
        let (bytes, marker) = match self.visibility.cover(offset, data) {
            Ok(parts) => parts,
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
        if bytes.has_remaining() {
            enqueue(
                &mut self.waiting,
                marker.destination().current(),
                marker.parameters().urgency(),
                offset,
            );
            self.pieces.insert(
                offset,
                Piece {
                    bytes,
                    marker,
                    state: PieceState::Waiting,
                },
            );
        }
        Ok(())
    }

    fn apply_reset(&mut self, retention: ResetRetention) -> Result<(), ApplyResetError> {
        let ResetRetention {
            final_size,
            reliable_size,
        } = retention;
        ReliableSizeBeyondFinalSizeError::check(final_size, reliable_size)
            .context(apply_reset_error::ReliableSizeBeyondFinalSizeSnafu)?;
        FinalSizeBeyondWrittenEndError::check(final_size, self.written_end)
            .context(apply_reset_error::FinalSizeBeyondWrittenEndSnafu)?;
        self.visibility
            .fix_final_size(final_size)
            .context(apply_reset_error::FixFinalSizeSnafu)?;

        // Data at and beyond the reliable size loses its eligibility for
        // sending, whatever its state; the piece straddling the reliable size
        // is cut there.
        self.split_at(reliable_size, |_| true);
        self.drop_from(reliable_size);
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

    fn destinations(&self) -> Vec<D::Current> {
        self.waiting
            .iter()
            .map(|group| group.destination.clone())
            .collect()
    }

    fn next(&self, destination: &D::Current) -> Option<NextSegment<'_, SendOptions<P, D>>> {
        let group = self
            .waiting
            .iter()
            .find(|group| group.destination == *destination)?;
        let &(_, offset) = group.pieces.first()?;
        let piece = self.pieces.get(&offset)?;
        Some(NextSegment {
            offset,
            len: piece.bytes.remaining(),
            marker: &piece.marker,
        })
    }

    fn select(&mut self, destination: &D::Current, max_len: usize) -> Option<SelectedData<B>> {
        if max_len == 0 {
            return None;
        }
        let NextSegment { offset, len, .. } = self.next(destination)?;
        if len > max_len {
            // The rest keeps waiting at the same position of the order.
            self.split_at(end_of(offset, max_len), |_| true);
        }
        let piece = self.pieces.get_mut(&offset)?;
        unqueue(
            &mut self.waiting,
            destination,
            piece.marker.parameters().urgency(),
            offset,
        );
        piece.state = PieceState::Selected;
        Some(SelectedData {
            offset,
            bytes: piece.bytes.clone(),
        })
    }

    fn on_acknowledged(&mut self, range: Range<VarInt>) -> Vec<D::Current> {
        let mut changed = Vec::new();
        if range.is_empty() {
            return changed;
        }
        self.split_at(range.start, |_| true);
        self.split_at(range.end, |_| true);
        for offset in self.offsets_in(&range) {
            let Some(piece) = self.pieces.remove(&offset) else {
                continue;
            };
            // Acknowledged, whatever its state: the data may go, and no later
            // loss finds it again.
            if piece.state == PieceState::Waiting {
                let destination = piece.marker.destination().current();
                unqueue(
                    &mut self.waiting,
                    &destination,
                    piece.marker.parameters().urgency(),
                    offset,
                );
                note_changed(&mut changed, destination);
            }
        }
        changed
    }

    fn on_lost(&mut self, range: Range<VarInt>) -> DestinationChanges<D::Current> {
        let mut changes = DestinationChanges::default();
        if range.is_empty() {
            return changes;
        }
        let selected = |state| state == PieceState::Selected;
        self.split_at(range.start, selected);
        self.split_at(range.end, selected);
        for offset in self.offsets_in(&range) {
            let Some(piece) = self.pieces.get_mut(&offset) else {
                continue;
            };
            // Waiting and exhausted pieces are not in flight: a loss
            // reported for them is of a transmission already settled.
            if piece.state != PieceState::Selected {
                continue;
            }
            let fallback = piece.marker.destination_mut().on_lost();
            self.apply_fallback(offset, fallback, &mut changes);
        }
        changes.exhausted = join_ranges(changes.exhausted);
        changes
    }

    fn on_unfulfilled(
        &mut self,
        destination: &D::Current,
        cause: Unfulfilled,
    ) -> DestinationChanges<D::Current> {
        let mut changes = DestinationChanges::default();
        let Some(index) = self
            .waiting
            .iter()
            .position(|group| group.destination == *destination)
        else {
            return changes;
        };
        let group = self.waiting.remove(index);
        note_changed(&mut changes.pending_changed, group.destination);
        for (_, offset) in group.pieces {
            let Some(piece) = self.pieces.get_mut(&offset) else {
                continue;
            };
            let fallback = piece.marker.destination_mut().on_unfulfilled(cause);
            self.apply_fallback(offset, fallback, &mut changes);
        }
        changes.exhausted = join_ranges(changes.exhausted);
        changes
    }
}
