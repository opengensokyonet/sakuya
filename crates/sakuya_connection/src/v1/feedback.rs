//! What version 1's frames leave in the record of a sent packet, and what
//! comes of it once the packet is delivered or lost.
//!
//! | Frame | Summary | Delivered | Lost |
//! | --- | --- | --- | --- |
//! | PADDING | [`PaddingSummary`] | nothing | nothing |
//! | ACK | [`AckSummary`]: the Largest Acknowledged and what was due before | the receive journals of the space stop reporting what lies below it (RFC 9000 §13.2.4) | the ACK obligation of the space owes again what it owed before (RFC 9000 §13.2.1), and the space's ACK intent is published again while an ACK frame is due |
//!
//! The summaries of the other frames come with their frame sources.
use sakuya_recovery::{
    ack_obligation::{AckDue, AckObligation},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    receive_journals::ReceiveJournals,
};
use sakuya_wire::{parts::Coproduct, v1::packet_number::PacketNumber};

use super::{
    Choices, Part,
    send::{AckIntent, SendTypes},
    send_planning::{AckIntentTicketOf, AckIntentTickets, CorePublishOutcome},
    spaces::AckObligationsOf,
};
use crate::{
    call::CallBundle,
    clock::InstantOf,
    feedback::{FeedbackSummaryPart, SendFeedback},
    others::OtherNodes,
    send_strategy::AnyActiveLinkPath,
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
    /// The PING of a probe timeout.
    ProbePing(ProbePingSummary),
}

/// The summary of the PING of a probe timeout: nothing is done when it is
/// acknowledged or lost; the probe timeout sends a new probe when it
/// expires again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ProbePingSummary;

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

/// Version 1's frame sources put their summaries into the sum of the
/// summaries of a composition, where version 1's comes first.
impl<I, Rest> From<FeedbackSummary<I>> for Coproduct<FeedbackSummary<I>, Rest> {
    fn from(summary: FeedbackSummary<I>) -> Self {
        Coproduct::Inl(summary)
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
///
/// A lost ACK frame also forgets the ticket of its space's ACK intent: the
/// frame consumed the intent, and when it was written and lost before the
/// tickets were read again, the ticket left looks like an intent still
/// waiting for the frame that is due again.
impl<T, L, V, Ij, Ia, Ik> SendFeedback<T, L, V, (Ij, Ia, Ik)> for Part
where
    T: Choices,
    L: PartList<T>,
    SendTypes<T, L>: CorePublishOutcome<AckIntent, AnyActiveLinkPath>,
    V: GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<AckIntentTickets<AckIntentTicketOf<T, L>>, Ik>,
{
    fn delivered<B: CallBundle>(
        lineage: &mut Lineage<'_, V>,
        _: &mut OtherNodes<'_, T, L, B>,
        space: PacketNumberSpaceKind,
        summary: FeedbackSummary<InstantOf<T>>,
    ) {
        match summary {
            FeedbackSummary::Padding(_) | FeedbackSummary::ProbePing(_) => {}
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
            FeedbackSummary::Padding(_) | FeedbackSummary::ProbePing(_) => {}
            FeedbackSummary::Ack(ack) => {
                if let Some(obligation) =
                    lineage.get_mut::<AckObligationsOf<T>, Ia>().get_mut(space)
                {
                    obligation.ack_lost(ack.before);
                }
                lineage
                    .get_mut::<AckIntentTickets<AckIntentTicketOf<T, L>>, Ik>()
                    .forget(space);
            }
        }
    }
}
