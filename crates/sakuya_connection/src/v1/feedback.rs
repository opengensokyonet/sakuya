//! What version 1's frames leave in the record of a sent packet, and what
//! comes of it once the packet is delivered or lost.
//!
//! | Frame | Summary | Delivered | Lost |
//! | --- | --- | --- | --- |
//! | PADDING | [`PaddingSummary`] | nothing | nothing |
//! | ACK | [`AckSummary`]: the Largest Acknowledged and what was due before | the receive journals of the space stop reporting what lies below it (RFC 9000 §13.2.4) | the ACK obligation of the space owes again what it owed before (RFC 9000 §13.2.1), and the space's ACK intent is published again while an ACK frame is due |
//! | PING of a probe timeout | [`ProbePingSummary`] | nothing | nothing: the next expiry of the probe timeout sends a new probe |
//! | RETIRE_CONNECTION_ID | [`RetireConnectionIdSummary`]: the sequence number | the retirement no longer waits for acknowledgment | the same frame is published again while the retirement waits for acknowledgment (RFC 9000 §13.3) |
//!
//! Each is the summary of one kind of version 1's frame sources
//! ([`FrameSources`]), and what comes of it is that source's
//! ([`AckFrameSource`](super::send::AckFrameSource),
//! [`ProbePingFrameSource`](super::send::ProbePingFrameSource), the
//! destination connection ID strategy,
//! [`PaddingFrameSource`](crate::write::PaddingFrameSource)).
use frunk_core::{HList, hlist_pat};
use sakuya_recovery::{ack_obligation::AckDue, packet_number_space::PacketNumberSpaceKind};
use sakuya_wire::{
    parts::{CNil, Coproduct},
    v1::packet_number::PacketNumber,
};

#[cfg(doc)]
use super::send::FrameSources;
use super::{
    Choices,
    send::{RetireConnectionIdSummary, SendTypes},
    send_planning::{SendStrategyCore, SendStrategyOf},
};
use crate::{
    clock::InstantOf,
    feedback::{FeedbackSummariesOf, FeedbackSummaryOf, PartsSendFeedback},
    send_strategy::SendStrategyTypes,
    take::{Lineage, Reborrow, Take, TakeEach},
    write::PaddingSummary,
};

/// The summary a frame of version 1 leaves in the record of a sent packet:
/// the sum of the summaries of [`FrameSources`], in their order.
///
/// `I` is the type of instants.
pub type FeedbackSummary<I> = Coproduct<
    PaddingSummary,
    Coproduct<
        AckSummary<I>,
        Coproduct<ProbePingSummary, Coproduct<RetireConnectionIdSummary, CNil>>,
    >,
>;

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
    /// written, as
    /// [`AckObligation::ack_written`](sakuya_recovery::ack_obligation::AckObligation::ack_written)
    /// gives it.
    pub before: AckDue<I>,
}

/// The packet writer puts PADDING into the sum of the summaries of a
/// composition through version 1's, which comes first.
impl<I, Rest> From<PaddingSummary> for Coproduct<FeedbackSummary<I>, Rest> {
    fn from(summary: PaddingSummary) -> Self {
        Coproduct::Inl(Coproduct::Inl(summary))
    }
}

/// The ACK frame source puts its summaries into the sum of the summaries
/// of a composition through version 1's, which comes first.
impl<I, Rest> From<AckSummary<I>> for Coproduct<FeedbackSummary<I>, Rest> {
    fn from(summary: AckSummary<I>) -> Self {
        Coproduct::Inl(Coproduct::Inr(Coproduct::Inl(summary)))
    }
}

/// The PING of a probe timeout puts its summaries into the sum of the
/// summaries of a composition through version 1's, which comes first.
impl<I, Rest> From<ProbePingSummary> for Coproduct<FeedbackSummary<I>, Rest> {
    fn from(summary: ProbePingSummary) -> Self {
        Coproduct::Inl(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(summary))))
    }
}

/// The destination connection ID strategy puts the summaries of its
/// RETIRE_CONNECTION_ID frames into the sum of the summaries of a
/// composition through version 1's, which comes first.
impl<I, Rest> From<RetireConnectionIdSummary> for Coproduct<FeedbackSummary<I>, Rest> {
    fn from(summary: RetireConnectionIdSummary) -> Self {
        Coproduct::Inl(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(
            Coproduct::Inl(summary),
        ))))
    }
}

// ---- feedback with the core lent ----

/// The core of the send strategy, as the connection node holds it.
type CoreOf<T, L> = SendStrategyCore<SendStrategyOf<T, L>>;

/// What is taken out of a lineage to lend to the frame sources: the core.
type CoreTakes<T, L> = HList![CoreOf<T, L>];

/// The lineage `V`, reborrowed for `'s`, without the core at `Ic`.
type WithoutCore<'s, T, L, V, Ic> =
    <<V as Reborrow<'s>>::Out as TakeEach<'s, CoreTakes<T, L>, Ic>>::Rest;

/// `V: CoreLentFeedback<T, L, H>`: the summaries of the composition of `T`
/// and `L` go back to their frame sources in a lineage of `V`, with the
/// core, which the lineage holds, lent to them to publish through.
///
/// `H` holds the place of the core and the positions of each part's
/// frame sources in the rest of the lineage.
pub trait CoreLentFeedback<T: Choices, L: FeedbackSummariesOf, H>: Sized {
    /// The packets of `space` that the frames of `summaries` were written
    /// into were acknowledged.
    fn delivered_each(
        lineage: &mut Lineage<'_, Self>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summaries: impl IntoIterator<Item = FeedbackSummaryOf<T, L>>,
    );

    /// The packets of `space` that the frames of `summaries` were written
    /// into were declared lost, or their send result is unknown, or their
    /// link path ended before they were settled.
    fn lost_each<'a>(
        lineage: &mut Lineage<'_, Self>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summaries: impl IntoIterator<Item = &'a FeedbackSummaryOf<T, L>>,
    ) where
        FeedbackSummaryOf<T, L>: 'a;
}

impl<T, L, V, Ic, Hf> CoreLentFeedback<T, L, (Ic, Hf)> for V
where
    T: Choices,
    L: FeedbackSummariesOf,
    SendTypes<T, L>: SendStrategyTypes,
    CoreOf<T, L>: 'static,
    for<'s> V: Reborrow<'s>,
    for<'s> <V as Reborrow<'s>>::Out: TakeEach<'s, CoreTakes<T, L>, Ic>,
    for<'s> L: PartsSendFeedback<T, L, WithoutCore<'s, T, L, V, Ic>, CoreOf<T, L>, Hf>,
{
    fn delivered_each(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summaries: impl IntoIterator<Item = FeedbackSummaryOf<T, L>>,
    ) {
        let (hlist_pat![core], mut rest) = Take::<CoreTakes<T, L>, Ic>::take(lineage.reborrow());
        for summary in summaries {
            <L as PartsSendFeedback<T, L, _, _, Hf>>::delivered(
                &mut rest, core, now, space, summary,
            );
        }
    }

    fn lost_each<'a>(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summaries: impl IntoIterator<Item = &'a FeedbackSummaryOf<T, L>>,
    ) where
        FeedbackSummaryOf<T, L>: 'a,
    {
        let (hlist_pat![core], mut rest) = Take::<CoreTakes<T, L>, Ic>::take(lineage.reborrow());
        for summary in summaries {
            <L as PartsSendFeedback<T, L, _, _, Hf>>::lost(&mut rest, core, now, space, summary);
        }
    }
}
