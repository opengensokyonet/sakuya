//! What version 1's frames leave in the record of a sent packet, and what
//! comes of it once the packet is delivered or lost.
//!
//! | Frame | Summary | Delivered | Lost |
//! | --- | --- | --- | --- |
//! | PADDING | [`PaddingSummary`] | nothing | nothing |
//! | ACK | [`AckSummary`]: the Largest Acknowledged and what was due before | the receive journals of the space stop reporting what lies below it (RFC 9000 §13.2.4) | the ACK obligation of the space owes again what it owed before (RFC 9000 §13.2.1), so the driver's content has the space's ACK again while an ACK frame is due |
//! | PING of a probe timeout | [`ProbePingSummary`] | nothing | nothing: the next expiry of the probe timeout sends a new probe |
//! | RETIRE_CONNECTION_ID | [`RetireConnectionIdSummary`]: the sequence number | the retirement no longer waits for acknowledgment | the retirement waits to be sent again while it waits for acknowledgment (RFC 9000 §13.3) |
//! | HANDSHAKE_DONE | [`HandshakeDoneSummary`] | the frame is delivered and not sent again | the frame waits to be sent again while no copy of it was acknowledged (RFC 9000 §13.3) |
//! | CRYPTO | [`CryptoSummary`]: the level, the offset and the length of the data | the bytes are acknowledged, and their data can go | the bytes still in flight are unsent again, so the driver's content has the level again (RFC 9000 §13.3) |
//! | STREAM | [`StreamSummary`]: the stream, the offset and length of the data, the FIN | the data is acknowledged; with the FIN and all data acknowledged the sending part is done | the data waits to be sent again, and the FIN if the stream was not reset (RFC 9000 §13.3) |
//! | RESET_STREAM | [`ResetStreamSummary`]: the stream and the final size | the sending part is done | the frame is sent again while the sending part is not done |
//! | STOP_SENDING | [`StopSendingSummary`]: the stream and the error code | nothing | the frame is sent again while the receiving part still needs it |
//! | MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS | [`MaxDataSummary`], [`MaxStreamDataSummary`], [`MaxStreamsSummary`]: the limit | nothing | the limit in effect, never lower than the one lost, is sent again while it is still advertised |
//! | DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED | [`DataBlockedSummary`], [`StreamDataBlockedSummary`], [`StreamsBlockedSummary`]: the limit | nothing | the frame is sent again while the sender is still blocked at that limit |
//! | PATH_RESPONSE | [`PathResponseSummary`]: nothing | nothing | nothing: a new challenge comes instead (RFC 9000 §13.3) |
//! | PING of a datagram size probe | [`PmtuProbeSummary`]: nothing | nothing | nothing: the probe's result goes to the probing policy from the packet's record |
//! | NEW_CONNECTION_ID | [`NewConnectionIdSummary`]: the sequence number | the connection ID is disclosed and not sent again | the same frame waits to be sent again while the connection ID is neither acknowledged nor retired by the peer (RFC 9000 §13.3) |
//! | PATH_CHALLENGE | [`PathChallengeSummary`]: nothing | nothing: an acknowledgment validates nothing (RFC 9000 §8.2.3) | nothing: the next challenge goes when it is due |
//! | NEW_TOKEN | [`NewTokenSummary`]: which of the tokens the connection issued | the token is delivered and not sent again | the token waits to be sent again while no copy of it was acknowledged (RFC 9000 §13.3) |
//!
//! Each is the summary of one kind of version 1's frame sources
//! ([`FrameSources`]), and what comes of it is that source's
//! ([`AckFrameSource`](super::send::AckFrameSource), the
//! destination connection ID strategy,
//! [`LineageCryptoFrameSource`](super::send::LineageCryptoFrameSource),
//! the [`Own`](super::Side::Own) data of the side, its
//! [`NewTokens`](super::Side::NewTokens) data,
//! [`PaddingFrameSource`](crate::write::PaddingFrameSource), for the
//! streams' frames the stream set, through
//! [`LineageStreamFrameSource`](super::streams::send::LineageStreamFrameSource),
//! and the local connection ID strategy). The PING of a probe,
//! PATH_RESPONSE, the PING of a datagram size probe and PATH_CHALLENGE need
//! nothing when they come back: their summaries go to
//! [`IgnoringFrameSource`](crate::frame_source::IgnoringFrameSource), not
//! to the pending frames of the link path that wrote them
//! ([`PendingProbePings`](super::send::PendingProbePings),
//! [`PendingPathResponse`](super::path_response::PendingPathResponse),
//! [`PendingPmtuProbe`](super::pmtu_probe::PendingPmtuProbe),
//! [`PathValidation`](super::path_validation::PathValidation)).
use nitori_tls::engine::CryptoLevel;
use sakuya_recovery::{ack_obligation::AckDue, packet_number_space::PacketNumberSpaceKind};
use sakuya_stream::send_options::destination::Unfulfilled;
use sakuya_wire::var_int::VarInt;
use sakuya_wire_v1::packet_number::PacketNumber;

#[cfg(doc)]
use super::send::FrameSources;
use super::{
    Choices,
    new_token::NewTokenSummary,
    path_response::PathResponseSummary,
    path_validation::PathChallengeSummary,
    pmtu_probe::PmtuProbeSummary,
    send::{RetireConnectionIdSummary, SendTypes},
    streams::send::{
        DataBlockedSummary, MaxDataSummary, MaxStreamDataSummary, MaxStreamsSummary,
        ResetStreamSummary, StopSendingSummary, StreamDataBlockedSummary, StreamSummary,
        StreamsBlockedSummary,
    },
};
use crate::{
    clock::InstantOf,
    connection_id::local::NewConnectionIdSummary,
    feedback::{FeedbackSummariesOf, FeedbackSummaryOf, PartsSendFeedback},
    send_strategy::{SendIntentsOf, SendStrategyTypes},
    take::{AppendEach, Lineage, OptionalRefs, Reborrow, WithOptionals},
    write::PaddingSummary,
};

/// The summary a frame of version 1 leaves in the record of a sent packet:
/// the sum of the summaries of [`FrameSources`], in their order.
///
/// `I` is the type of instants.
pub type FeedbackSummary<I> = frunk_core::Coprod!(
    PaddingSummary,
    AckSummary<I>,
    ProbePingSummary,
    RetireConnectionIdSummary,
    HandshakeDoneSummary,
    CryptoSummary,
    StreamSummary,
    ResetStreamSummary,
    StopSendingSummary,
    MaxDataSummary,
    MaxStreamDataSummary,
    MaxStreamsSummary,
    DataBlockedSummary,
    StreamDataBlockedSummary,
    StreamsBlockedSummary,
    NewConnectionIdSummary,
    PathResponseSummary,
    PmtuProbeSummary,
    PathChallengeSummary,
    NewTokenSummary,
);

/// The summary of a CRYPTO frame written into a packet: which bytes of
/// which level it carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoSummary {
    /// The encryption level of the data.
    pub level: CryptoLevel,
    /// The offset of the data in the level's stream.
    pub offset: VarInt,
    /// The length of the data.
    pub len: usize,
}

/// The summary of a HANDSHAKE_DONE frame written into a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HandshakeDoneSummary;

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

// ---- feedback in a lineage ----

/// `V: LineageFeedback<T, L, X, H>`: the summaries of the composition of
/// `T` and `L` go back to their frame sources in a lineage of `V`, with the
/// components `X` of the established layer (a list of component types,
/// [`EstablishedSourceComponentsOfParts`](crate::frame_source::EstablishedSourceComponentsOfParts)),
/// which are not in the lineage, borrowed again from `established` and
/// appended to it for the frame sources that find them there; each `None`
/// when there is no established layer, and then those sources take nothing
/// back.
///
/// `H` holds the positions of each part's frame sources in the lineage.
pub trait LineageFeedback<T: Choices, L: FeedbackSummariesOf, X: OptionalRefs, H>: Sized {
    /// The packets of `space` that the frames of `summaries` were written
    /// into were acknowledged.
    fn delivered_each(
        lineage: &mut Lineage<'_, Self>,
        established: &mut X::Optional<'_>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summaries: impl IntoIterator<Item = FeedbackSummaryOf<T, L>>,
    );

    /// The packets of `space` that the frames of `summaries` were written
    /// into were declared lost, or their send result is unknown, or their
    /// link path ended before they were settled.
    fn lost_each<'a>(
        lineage: &mut Lineage<'_, Self>,
        established: &mut X::Optional<'_>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summaries: impl IntoIterator<Item = &'a FeedbackSummaryOf<T, L>>,
    ) where
        FeedbackSummaryOf<T, L>: 'a;

    /// The send strategy did not fulfil `intents`, for `cause`: each goes
    /// back to the frame source it belongs to, whatever kind of packet
    /// would have carried it.
    fn unfulfilled_each(
        lineage: &mut Lineage<'_, Self>,
        established: &mut X::Optional<'_>,
        now: InstantOf<T>,
        intents: impl IntoIterator<Item = <SendTypes<T, L> as SendStrategyTypes>::SendIntents>,
        cause: Unfulfilled,
    ) where
        SendTypes<T, L>: SendStrategyTypes;
}

/// The positions the driver records for the frame sources that find the
/// components of the established layer, past the components of the
/// lineage's nodes, are ignored: whoever borrows the established layer to
/// append them records that layer as taken itself.
impl<T, L, V, X, H> LineageFeedback<T, L, X, H> for V
where
    T: Choices,
    L: FeedbackSummariesOf + SendIntentsOf,
    SendTypes<T, L>: SendStrategyTypes<SendIntents = <L as SendIntentsOf>::SendIntents>,
    X: OptionalRefs,
    for<'s> V: Reborrow<'s>,
    for<'s> <V as Reborrow<'s>>::Out: AppendEach<X::Optional<'s>>,
    for<'s> L: PartsSendFeedback<T, L, WithOptionals<'s, <V as Reborrow<'s>>::Out, X>, H>,
{
    fn delivered_each(
        lineage: &mut Lineage<'_, V>,
        established: &mut X::Optional<'_>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summaries: impl IntoIterator<Item = FeedbackSummaryOf<T, L>>,
    ) {
        let mut lineage = lineage
            .reborrow()
            .append_optionals::<X>(X::reborrow(established));
        for summary in summaries {
            <L as PartsSendFeedback<T, L, _, H>>::delivered(&mut lineage, now, space, summary);
        }
    }

    fn lost_each<'a>(
        lineage: &mut Lineage<'_, V>,
        established: &mut X::Optional<'_>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summaries: impl IntoIterator<Item = &'a FeedbackSummaryOf<T, L>>,
    ) where
        FeedbackSummaryOf<T, L>: 'a,
    {
        let mut lineage = lineage
            .reborrow()
            .append_optionals::<X>(X::reborrow(established));
        for summary in summaries {
            <L as PartsSendFeedback<T, L, _, H>>::lost(&mut lineage, now, space, summary);
        }
    }

    fn unfulfilled_each(
        lineage: &mut Lineage<'_, V>,
        established: &mut X::Optional<'_>,
        now: InstantOf<T>,
        intents: impl IntoIterator<Item = <L as SendIntentsOf>::SendIntents>,
        cause: Unfulfilled,
    ) {
        let mut lineage = lineage
            .reborrow()
            .append_optionals::<X>(X::reborrow(established));
        for intent in intents {
            <L as PartsSendFeedback<T, L, _, H>>::unfulfilled(&mut lineage, now, &intent, cause);
        }
    }
}
