//! What version 1's frames leave in the record of a sent packet, and what
//! comes of it once the packet is delivered or lost.
//!
//! | Frame | Summary | Delivered | Lost |
//! | --- | --- | --- | --- |
//! | PADDING | [`PaddingSummary`] | nothing | nothing |
//! | ACK | [`AckSummary`]: the Largest Acknowledged and what was due before | the receive journals of the space stop reporting what lies below it (RFC 9000 §13.2.4) | the ACK obligation of the space owes again what it owed before (RFC 9000 §13.2.1) |
//!
//! The summaries of the other frames come with their frame sources.
use sakuya_recovery::{
    ack_obligation::{AckDue, AckObligation},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    receive_journals::ReceiveJournals,
};
use sakuya_wire::{parts::Coproduct, v1::packet_number::PacketNumber};

use super::{Choices, Part, spaces::AckObligationsOf};
use crate::{
    call::CallBundle,
    clock::InstantOf,
    feedback::{FeedbackSummaryPart, SendFeedback},
    others::OtherNodes,
    share::PartList,
    take::{GetAt, Lineage},
    write::PaddingSummary,
};

/// The summary a frame of version 1 leaves in the record of a sent packet.
///
/// `I` is the type of instants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackSummary<I> {
    /// PADDING, which the packet writer writes.
    Padding(PaddingSummary),
    /// An ACK frame.
    Ack(AckSummary<I>),
}

/// The summary of an ACK frame written into a packet.
///
/// `I` is the type of instants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckSummary<I> {
    /// The frame's Largest Acknowledged.
    pub largest: PacketNumber,
    /// What the ACK obligation of the space owed before the frame was
    /// written, as [`AckObligation::ack_written`] gives it.
    pub before: AckDue<I>,
}

/// The packet writer puts PADDING into version 1's summary.
impl<I> From<PaddingSummary> for FeedbackSummary<I> {
    fn from(summary: PaddingSummary) -> Self {
        Self::Padding(summary)
    }
}

/// The packet writer puts PADDING into the sum of the summaries of a
/// composition through version 1's, which comes first.
impl<I, Rest> From<PaddingSummary> for Coproduct<FeedbackSummary<I>, Rest> {
    fn from(summary: PaddingSummary) -> Self {
        Coproduct::Inl(FeedbackSummary::Padding(summary))
    }
}

/// Version 1's frames leave [`FeedbackSummary`].
impl FeedbackSummaryPart for Part {
    type FeedbackSummary<I> = FeedbackSummary<I>;
}

/// The summaries of version 1 go to the receive journals and the ACK
/// obligation of the packet's space, of the logical path in the lineage.
/// A space that is gone takes nothing.
impl<T, L, V, Ij, Ia> SendFeedback<T, L, V, (Ij, Ia)> for Part
where
    T: Choices,
    L: PartList<T>,
    V: GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<AckObligationsOf<T>, Ia>,
{
    fn delivered<B: CallBundle>(
        lineage: &mut Lineage<'_, V>,
        _: &mut OtherNodes<'_, T, L, B>,
        space: PacketNumberSpaceKind,
        summary: FeedbackSummary<InstantOf<T>>,
    ) {
        match summary {
            FeedbackSummary::Padding(_) => {}
            FeedbackSummary::Ack(ack) => {
                if let Some(journals) = lineage
                    .get_mut::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>()
                    .get_mut(space)
                {
                    journals.acknowledged_up_to(ack.largest);
                }
            }
        }
    }

    fn lost<B: CallBundle>(
        lineage: &mut Lineage<'_, V>,
        _: &mut OtherNodes<'_, T, L, B>,
        space: PacketNumberSpaceKind,
        summary: &FeedbackSummary<InstantOf<T>>,
    ) {
        match summary {
            FeedbackSummary::Padding(_) => {}
            FeedbackSummary::Ack(ack) => {
                if let Some(obligation) =
                    lineage.get_mut::<AckObligationsOf<T>, Ia>().get_mut(space)
                {
                    obligation.ack_lost(ack.before);
                }
            }
        }
    }
}
