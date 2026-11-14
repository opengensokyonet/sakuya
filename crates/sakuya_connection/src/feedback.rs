//! What the frames of a sent packet leave in its record, and how the record
//! hands it back to the frame sources once the packet is delivered or lost.
//!
//! Each frame written into a packet leaves one feedback summary in the
//! packet's record. A part's summary is the sum of the summaries of the
//! kinds of frame sources it lists
//! ([`FrameSourceKinds::Summaries`]); the composition's summary is the sum
//! of the parts' summaries in the order of the list of parts
//! ([`FeedbackSummaryOf`]), and the send journals of every packet number
//! space keep it. The summaries carry the instant type of the choices, so
//! that a summary can hold a deadline; they do not depend on the list of
//! parts.
//!
//! When a packet is acknowledged, each of its summaries goes back by value
//! to the frame source that wrote it: the packet is delivered. When it is
//! declared lost, each is lent to the source, and stays in the record kept
//! for a late acknowledgment, which then delivers it. The list of parts
//! hands each summary to the part it belongs to, and the part's list of
//! kinds to the source of its kind ([`PartsSendFeedback`]), with the
//! publisher the sources publish through.
//!
//! Feedback is given where the packet is settled: in the dispatch of an
//! ACK frame on a logical path, in an expiry of a link path's recovery
//! layer that declares packets lost, in a sending call whose datagrams'
//! send result is unknown, and in the end of a link path, which hands back
//! what it had not settled as lost. Each sees the lineage of its node, with
//! what it took out of it; the feedback traits are generic over that
//! lineage (`V`), so that the same frame sources serve them all.
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::parts::{CNil, Coproduct, HCons, HNil};

use crate::{
    clock::{ConnectionChoices, InstantOf},
    frame_source::{FeedFrameSources, FrameSourceKinds},
    send_strategy::SendIntentPart,
    take::Lineage,
};

/// The summaries of a list of parts: the sum of the summaries of the
/// frame sources each part lists, in the order of the parts.
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

impl<P: SendIntentPart, Ps: FeedbackSummariesOf> FeedbackSummariesOf for HCons<P, Ps> {
    type FeedbackSummaries<I> =
        Coproduct<<P::FrameSources as FrameSourceKinds>::Summaries<I>, Ps::FeedbackSummaries<I>>;
}

/// The summary of one frame of a connection of the choices `T` and the
/// list of parts `L`.
pub type FeedbackSummaryOf<T, L> = <L as FeedbackSummariesOf>::FeedbackSummaries<InstantOf<T>>;

/// Handing a summary back to the frame source of a list of parts that
/// wrote it.
///
/// It is implemented for every list whose parts' lists of frame sources
/// implement [`FeedFrameSources`]; `L` is the whole composition, `V` the
/// lineage where the feedback is given, `Pb` the publisher lent to the
/// sources and `Hs` the positions of each part's impl. Each summary comes
/// with the packet number space of the packet it was written into.
pub trait PartsSendFeedback<T: ConnectionChoices, L, V, Pb, Hs>: FeedbackSummariesOf {
    /// The packet the frame of `summary` was written into was acknowledged.
    fn delivered(
        lineage: &mut Lineage<'_, V>,
        publish: &mut Pb,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: Self::FeedbackSummaries<InstantOf<T>>,
    );

    /// The packet the frame of `summary` was written into was declared
    /// lost, or its send result is unknown, or its link path ended before
    /// it was settled. `summary` stays in the packet's record while it is
    /// kept, for a late acknowledgment.
    fn lost(
        lineage: &mut Lineage<'_, V>,
        publish: &mut Pb,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: &Self::FeedbackSummaries<InstantOf<T>>,
    );
}

impl<T: ConnectionChoices, L, V, Pb> PartsSendFeedback<T, L, V, Pb, HNil> for HNil {
    fn delivered(
        _: &mut Lineage<'_, V>,
        _: &mut Pb,
        _: InstantOf<T>,
        _: PacketNumberSpaceKind,
        summary: CNil,
    ) {
        match summary {}
    }

    fn lost(
        _: &mut Lineage<'_, V>,
        _: &mut Pb,
        _: InstantOf<T>,
        _: PacketNumberSpaceKind,
        summary: &CNil,
    ) {
        match *summary {}
    }
}

impl<T, L, V, Pb, P, Ps, H, Hs> PartsSendFeedback<T, L, V, Pb, HCons<H, Hs>> for HCons<P, Ps>
where
    T: ConnectionChoices,
    P: SendIntentPart,
    P::FrameSources: FeedFrameSources<T, L, V, Pb, H>,
    Ps: PartsSendFeedback<T, L, V, Pb, Hs>,
{
    fn delivered(
        lineage: &mut Lineage<'_, V>,
        publish: &mut Pb,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: Self::FeedbackSummaries<InstantOf<T>>,
    ) {
        match summary {
            Coproduct::Inl(summary) => {
                <P::FrameSources as FeedFrameSources<T, L, V, Pb, H>>::delivered(
                    lineage, publish, now, space, summary,
                );
            }
            Coproduct::Inr(summary) => Ps::delivered(lineage, publish, now, space, summary),
        }
    }

    fn lost(
        lineage: &mut Lineage<'_, V>,
        publish: &mut Pb,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: &Self::FeedbackSummaries<InstantOf<T>>,
    ) {
        match summary {
            Coproduct::Inl(summary) => {
                <P::FrameSources as FeedFrameSources<T, L, V, Pb, H>>::lost(
                    lineage, publish, now, space, summary,
                );
            }
            Coproduct::Inr(summary) => Ps::lost(lineage, publish, now, space, summary),
        }
    }
}
