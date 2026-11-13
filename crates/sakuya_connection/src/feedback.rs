//! What the frames of a sent packet leave in its record, and how the record
//! hands it back to the parts once the packet is delivered or lost.
//!
//! Each frame written into a packet leaves one feedback summary in the
//! packet's record. Each part of a composition gives the summary of its own
//! frames ([`FeedbackSummaryPart`]); the composition's summary is the sum of
//! those summaries in the order of the list of parts
//! ([`FeedbackSummaryOf`]), and the send journals of every packet number
//! space keep it. The summaries carry the instant type of the choices, so
//! that a summary can hold a deadline; they do not depend on the list of
//! parts.
//!
//! When a packet is acknowledged, each of its summaries goes back by value
//! to the part that wrote it: the packet is delivered. When it is declared
//! lost, each is lent to the part, and stays in the record kept for a late
//! acknowledgment, which then delivers it. A part handles only its own
//! summaries ([`SendFeedback`]); the list of parts hands each to the part it
//! belongs to ([`PartsSendFeedback`]).
//!
//! Feedback is given where the packet is settled: in the dispatch of an
//! ACK frame on a logical path, in an expiry of a link path's recovery
//! layer that declares packets lost, and in the end of a link path, which
//! hands back what it had not settled as lost. Each sees other components
//! of the tree: the lineage of its node, with what it took out of it, and
//! the other nodes. The feedback traits are generic over that lineage
//! (`V`), so that the same implementation of a part serves the three.
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::parts::{CNil, Coproduct, HCons, HNil};

use crate::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    others::OtherNodes,
    share::PartList,
    take::Lineage,
};

/// The summary a part's frames leave in the record of a sent packet.
///
/// It is implemented by the marker type of each part. `I` is the type of
/// instants of the composition's choices.
pub trait FeedbackSummaryPart {
    /// The summary of one frame of the part.
    type FeedbackSummary<I>;
}

/// The summaries of a list of parts: the sum of the summaries of the parts
/// ([`FeedbackSummaryPart::FeedbackSummary`]) in the order of the parts.
///
/// It is implemented for `HNil` and for `HCons<P, Ps>` of a part `P` and a
/// list of parts `Ps`.
pub trait FeedbackSummariesOf {
    /// The sum: a `Coproduct` that ends in `CNil`.
    type FeedbackSummaries<I>;
}

impl FeedbackSummariesOf for HNil {
    type FeedbackSummaries<I> = CNil;
}

impl<P: FeedbackSummaryPart, Ps: FeedbackSummariesOf> FeedbackSummariesOf for HCons<P, Ps> {
    type FeedbackSummaries<I> = Coproduct<P::FeedbackSummary<I>, Ps::FeedbackSummaries<I>>;
}

/// The summary of one frame of a connection of the choices `T` and the
/// list of parts `L`.
pub type FeedbackSummaryOf<T, L> = <L as FeedbackSummariesOf>::FeedbackSummaries<InstantOf<T>>;

/// How a part takes back the summaries of its frames: implemented by the
/// marker type of the part.
///
/// `L` is the composition's list of parts, `V` the lineage where the
/// feedback is given and `H` what the impl infers the positions of the
/// components it takes by. Each summary comes with the packet number space
/// of the packet it was written into.
pub trait SendFeedback<T: ConnectionChoices, L: PartList<T>, V, H>: FeedbackSummaryPart {
    /// The packet the frame of `summary` was written into was acknowledged.
    fn delivered<B: CallBundle>(
        lineage: &mut Lineage<'_, V>,
        others: &mut OtherNodes<'_, T, L, B>,
        space: PacketNumberSpaceKind,
        summary: Self::FeedbackSummary<InstantOf<T>>,
    );

    /// The packet the frame of `summary` was written into was declared
    /// lost, or its send result is unknown, or its link path ended before
    /// it was settled. `summary` stays in the packet's record while it is
    /// kept, for a late acknowledgment.
    fn lost<B: CallBundle>(
        lineage: &mut Lineage<'_, V>,
        others: &mut OtherNodes<'_, T, L, B>,
        space: PacketNumberSpaceKind,
        summary: &Self::FeedbackSummary<InstantOf<T>>,
    );
}

/// Handing a summary back to the part of a list that wrote it.
///
/// It is implemented for every list whose parts implement [`SendFeedback`];
/// `L` is the whole composition and `Hs` the positions of each part's impl.
pub trait PartsSendFeedback<T: ConnectionChoices, L: PartList<T>, V, Hs>:
    FeedbackSummariesOf
{
    /// The packet the frame of `summary` was written into was acknowledged.
    fn delivered<B: CallBundle>(
        lineage: &mut Lineage<'_, V>,
        others: &mut OtherNodes<'_, T, L, B>,
        space: PacketNumberSpaceKind,
        summary: Self::FeedbackSummaries<InstantOf<T>>,
    );

    /// The packet the frame of `summary` was written into was declared
    /// lost; see [`SendFeedback::lost`].
    fn lost<B: CallBundle>(
        lineage: &mut Lineage<'_, V>,
        others: &mut OtherNodes<'_, T, L, B>,
        space: PacketNumberSpaceKind,
        summary: &Self::FeedbackSummaries<InstantOf<T>>,
    );
}

impl<T: ConnectionChoices, L: PartList<T>, V> PartsSendFeedback<T, L, V, HNil> for HNil {
    fn delivered<B: CallBundle>(
        _: &mut Lineage<'_, V>,
        _: &mut OtherNodes<'_, T, L, B>,
        _: PacketNumberSpaceKind,
        summary: CNil,
    ) {
        match summary {}
    }

    fn lost<B: CallBundle>(
        _: &mut Lineage<'_, V>,
        _: &mut OtherNodes<'_, T, L, B>,
        _: PacketNumberSpaceKind,
        summary: &CNil,
    ) {
        match *summary {}
    }
}

impl<T, L, V, P, Ps, H, Hs> PartsSendFeedback<T, L, V, HCons<H, Hs>> for HCons<P, Ps>
where
    T: ConnectionChoices,
    L: PartList<T>,
    P: SendFeedback<T, L, V, H>,
    Ps: PartsSendFeedback<T, L, V, Hs>,
{
    fn delivered<B: CallBundle>(
        lineage: &mut Lineage<'_, V>,
        others: &mut OtherNodes<'_, T, L, B>,
        space: PacketNumberSpaceKind,
        summary: Self::FeedbackSummaries<InstantOf<T>>,
    ) {
        match summary {
            Coproduct::Inl(summary) => P::delivered(lineage, others, space, summary),
            Coproduct::Inr(summary) => Ps::delivered(lineage, others, space, summary),
        }
    }

    fn lost<B: CallBundle>(
        lineage: &mut Lineage<'_, V>,
        others: &mut OtherNodes<'_, T, L, B>,
        space: PacketNumberSpaceKind,
        summary: &Self::FeedbackSummaries<InstantOf<T>>,
    ) {
        match summary {
            Coproduct::Inl(summary) => P::lost(lineage, others, space, summary),
            Coproduct::Inr(summary) => Ps::lost(lineage, others, space, summary),
        }
    }
}
