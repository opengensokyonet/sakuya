//! What the streams send through the send strategy: the intents of the
//! nine frames of streams and flow control ([`StreamIntent`]), the summaries
//! their frames leave in a packet's record, and the frame sources that write
//! them, one kind for each frame.
//!
//! Every intent of the streams goes through the strategy's intake, from the
//! application's threads and from the driver alike; the stream set keeps
//! the tickets, under the lock of the component each frame is about, and
//! resizes or withdraws them there. Publishing one gives back the ticket of
//! the intake ([`StreamIntentHandle`]).
//!
//! A frame source of the streams is found in the lineage through the
//! stream set of the established layer, which the lend appends to it, and
//! the intake in the connection node. Without the layer it writes nothing
//! and takes nothing back: the streams ended with the layer.
//!
//! | Frame | Kind | Item | Summary |
//! | --- | --- | --- | --- |
//! | STREAM | [`StreamFrames`] | stream ID and planned urgency | [`StreamSummary`]: stream ID, offset, length, FIN |
//! | RESET_STREAM, or the reset frame of the reset kind | [`ResetStreamFrames`] | stream ID | [`ResetStreamSummary`]: stream ID, final size, reliable size |
//! | STOP_SENDING | [`StopSendingFrames`] | stream ID | [`StopSendingSummary`]: stream ID, error code |
//! | MAX_DATA | [`MaxDataFrames`] | — | [`MaxDataSummary`]: the limit |
//! | MAX_STREAM_DATA | [`MaxStreamDataFrames`] | stream ID | [`MaxStreamDataSummary`]: stream ID, the limit |
//! | MAX_STREAMS | [`MaxStreamsFrames`] | directionality | [`MaxStreamsSummary`]: directionality, the limit |
//! | DATA_BLOCKED | [`DataBlockedFrames`] | — | [`DataBlockedSummary`]: the limit |
//! | STREAM_DATA_BLOCKED | [`StreamDataBlockedFrames`] | stream ID | [`StreamDataBlockedSummary`]: stream ID, the limit |
//! | STREAMS_BLOCKED | [`StreamsBlockedFrames`] | directionality | [`StreamsBlockedSummary`]: directionality, the limit |

use core::marker::PhantomData;

use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream::send_options::{
    destination::Unfulfilled,
    urgency::{SendUrgency, Urgency},
};
use sakuya_wire::{
    v1::{
        application_error::ApplicationErrorCode,
        stream_count::StreamCount,
        stream_id::{Directionality, StreamId},
    },
    var_int::{VarInt, VarIntField},
};

use super::{
    StreamSet, StreamsOf,
    resets::{StreamResets, StreamResetsOf, StreamResetsOfParts},
};
use crate::v1::SendParametersOf;
use crate::{
    clock::InstantOf,
    feedback::InjectSummary,
    frame_source::{FindFrameSource, FrameSource, FrameSourceKind},
    send_strategy::{
        AnyActiveLinkPath, IntentTicketResize, IntentTicketWithdraw, MinimumLengths, SendIntent,
        SendIntentHandle, SendIntentIntake, SharedPublishTo,
        ranked::{RankedIntent, SendPriority, SendRank},
    },
    take::{GetAt, GetOptionalAt, Lineage},
    v1::{
        Choices, CloseCauseOf,
        send::{FrameSourceId, SendTypes},
        send_planning::{
            HostSendStrategyTypes, IntakeOf, IntakePublishOutcome, SendStrategyIntake,
        },
    },
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

// ---- intents ----

/// A frame of streams or flow control is to be sent (`StreamIntent`): one
/// variant for each of the nine frames, with what its frame source finds
/// the frame by and the least room it needs.
///
/// `P` is the parameters application data is sent with; only STREAM has
/// them, those of the next data of its destination. The others need their
/// frame as it encodes now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamIntent<P> {
    /// STREAM frames of a stream's data, or its FIN, for its one
    /// destination.
    Stream {
        /// The stream.
        stream_id: StreamId,
        /// The parameters of the next data.
        parameters: P,
        /// The least room: a frame with one byte of the next data, or with
        /// the FIN alone; without a Length field as the last frame.
        min: MinimumLengths,
    },
    /// A stream's RESET_STREAM frame.
    ResetStream {
        /// The stream.
        stream_id: StreamId,
        /// The length of the frame.
        len: usize,
    },
    /// A stream's STOP_SENDING frame.
    StopSending {
        /// The stream.
        stream_id: StreamId,
        /// The length of the frame.
        len: usize,
    },
    /// The connection's MAX_DATA frame.
    MaxData {
        /// The length of the frame.
        len: usize,
    },
    /// A stream's MAX_STREAM_DATA frame.
    MaxStreamData {
        /// The stream.
        stream_id: StreamId,
        /// The length of the frame.
        len: usize,
    },
    /// The MAX_STREAMS frame of the peer's streams of one directionality.
    MaxStreams {
        /// The streams it limits.
        directionality: Directionality,
        /// The length of the frame.
        len: usize,
    },
    /// The connection's DATA_BLOCKED frame.
    DataBlocked {
        /// The length of the frame.
        len: usize,
    },
    /// A stream's STREAM_DATA_BLOCKED frame.
    StreamDataBlocked {
        /// The stream.
        stream_id: StreamId,
        /// The length of the frame.
        len: usize,
    },
    /// The STREAMS_BLOCKED frame of this side's streams of one
    /// directionality.
    StreamsBlocked {
        /// The streams it is about.
        directionality: Directionality,
        /// The length of the frame.
        len: usize,
    },
}

/// What a frame source of the streams finds an intent by
/// (`StreamIntentKey`): the frame, and the stream or the directionality it
/// is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamIntentKey {
    /// STREAM frames of the stream.
    Stream(StreamId),
    /// The RESET_STREAM frame of the stream.
    ResetStream(StreamId),
    /// The STOP_SENDING frame of the stream.
    StopSending(StreamId),
    /// The MAX_DATA frame.
    MaxData,
    /// The MAX_STREAM_DATA frame of the stream.
    MaxStreamData(StreamId),
    /// The MAX_STREAMS frame of the directionality.
    MaxStreams(Directionality),
    /// The DATA_BLOCKED frame.
    DataBlocked,
    /// The STREAM_DATA_BLOCKED frame of the stream.
    StreamDataBlocked(StreamId),
    /// The STREAMS_BLOCKED frame of the directionality.
    StreamsBlocked(Directionality),
}

impl<P> StreamIntent<P> {
    /// What the intent's frame source finds it by.
    pub fn key(&self) -> StreamIntentKey {
        match *self {
            Self::Stream { stream_id, .. } => StreamIntentKey::Stream(stream_id),
            Self::ResetStream { stream_id, .. } => StreamIntentKey::ResetStream(stream_id),
            Self::StopSending { stream_id, .. } => StreamIntentKey::StopSending(stream_id),
            Self::MaxData { .. } => StreamIntentKey::MaxData,
            Self::MaxStreamData { stream_id, .. } => StreamIntentKey::MaxStreamData(stream_id),
            Self::MaxStreams { directionality, .. } => StreamIntentKey::MaxStreams(directionality),
            Self::DataBlocked { .. } => StreamIntentKey::DataBlocked,
            Self::StreamDataBlocked { stream_id, .. } => {
                StreamIntentKey::StreamDataBlocked(stream_id)
            }
            Self::StreamsBlocked { directionality, .. } => {
                StreamIntentKey::StreamsBlocked(directionality)
            }
        }
    }
}

impl StreamIntentKey {
    /// The frame source of the intents of this key.
    pub fn frame_source(self) -> FrameSourceId {
        match self {
            Self::Stream(_) => FrameSourceId::Stream,
            Self::ResetStream(_) => FrameSourceId::ResetStream,
            Self::StopSending(_) => FrameSourceId::StopSending,
            Self::MaxData => FrameSourceId::MaxData,
            Self::MaxStreamData(_) => FrameSourceId::MaxStreamData,
            Self::MaxStreams(_) => FrameSourceId::MaxStreams,
            Self::DataBlocked => FrameSourceId::DataBlocked,
            Self::StreamDataBlocked(_) => FrameSourceId::StreamDataBlocked,
            Self::StreamsBlocked(_) => FrameSourceId::StreamsBlocked,
        }
    }
}

/// The least room of STREAM frames of `stream_id` starting at `offset`:
/// with one byte of data when `data`, otherwise with no data and the FIN.
/// As the last frame of a packet it has no Length field; otherwise a Length
/// field of one byte, which holds the length of one byte or none.
pub fn shortest_stream_frame(stream_id: StreamId, offset: VarInt, data: bool) -> MinimumLengths {
    let offset_len = if offset == VarInt::ZERO {
        0
    } else {
        VarIntField::shortest(offset).encoded_len()
    };
    let as_last =
        1 + VarIntField::shortest(stream_id).encoded_len() + offset_len + usize::from(data);
    MinimumLengths {
        with_length: as_last + 1,
        as_last,
    }
}

impl<P> SendIntent for StreamIntent<P> {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        self.key().frame_source()
    }

    fn min_lengths(&self) -> MinimumLengths {
        match *self {
            Self::Stream { min, .. } => min,
            Self::ResetStream { len, .. }
            | Self::StopSending { len, .. }
            | Self::MaxData { len }
            | Self::MaxStreamData { len, .. }
            | Self::MaxStreams { len, .. }
            | Self::DataBlocked { len }
            | Self::StreamDataBlocked { len, .. }
            | Self::StreamsBlocked { len, .. } => MinimumLengths {
                with_length: len,
                as_last: len,
            },
        }
    }
}

/// STREAM is application data, by the urgency of its parameters; it does
/// not hold its place, and stays after writing: its source writes what it
/// can and resizes or withdraws it. The other eight are control frames that
/// hold their place, consumed as they are written.
impl<P: SendUrgency> RankedIntent for StreamIntent<P> {
    fn rank(&self) -> SendRank {
        match self {
            Self::Stream { .. } => SendRank {
                priority: SendPriority::ApplicationData,
                holds_place: false,
            },
            _ => SendRank {
                priority: SendPriority::Control,
                holds_place: true,
            },
        }
    }

    fn urgency(&self) -> sakuya_stream::send_options::urgency::Urgency {
        match self {
            Self::Stream { parameters, .. } => parameters.urgency(),
            _ => sakuya_stream::send_options::urgency::Urgency::default(),
        }
    }

    fn is_stream(&self) -> bool {
        matches!(self, Self::Stream { .. })
    }

    fn stays_after_writing(&self) -> bool {
        self.is_stream()
    }
}

/// A handle that publishes the intents of the streams, with the parameters
/// `S`, for any active link path and gives back the ticket `K`
/// (`StreamIntentHandle`): what the stream set publishes through.
pub trait StreamIntentHandle<S, K>:
    SendIntentHandle<StreamIntent<S>, AnyActiveLinkPath, Outcome = K>
{
}

impl<H, S, K> StreamIntentHandle<S, K> for H where
    H: SendIntentHandle<StreamIntent<S>, AnyActiveLinkPath, Outcome = K>
{
}

/// The ticket of a stream intent of the choices `T` and the list of parts
/// `L`: what the intake gives back for it.
pub type StreamIntentTicketOf<T, L> = <SendTypes<T, L> as IntakePublishOutcome<
    StreamIntent<SendParametersOf<T>>,
    AnyActiveLinkPath,
>>::Outcome;

/// The handle the intake of the choices `T` and the list of parts `L` gives
/// for the stream intents at the place `Idx`.
pub type StreamIntentHandleOf<T, L, Idx> = <IntakeOf<T, L> as SendIntentIntake<
    AnyActiveLinkPath,
>>::Handle<StreamIntent<SendParametersOf<T>>, Idx>;

// ---- summaries ----

/// The summary of a STREAM frame written into a packet: which data of which
/// stream it carried, and whether the FIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSummary {
    /// The stream.
    pub stream_id: StreamId,
    /// The offset of the data.
    pub offset: VarInt,
    /// The length of the data.
    pub len: usize,
    /// Whether the frame carried the FIN.
    pub fin: bool,
}

/// The summary of a reset frame written into a packet: the frame of the
/// reset target the stream set's reset kind gives, RESET_STREAM or another
/// kind's, such as RESET_STREAM_AT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetStreamSummary {
    /// The stream.
    pub stream_id: StreamId,
    /// The final size the frame carried.
    pub final_size: VarInt,
    /// The size up to which the frame kept the data's delivery: 0 for
    /// RESET_STREAM, the Reliable Size of RESET_STREAM_AT.
    pub reliable_size: VarInt,
}

/// The summary of a STOP_SENDING frame written into a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopSendingSummary {
    /// The stream.
    pub stream_id: StreamId,
    /// The error code the frame carried.
    pub application_error_code: ApplicationErrorCode,
}

/// The summary of a MAX_DATA frame written into a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxDataSummary {
    /// The limit the frame carried.
    pub maximum_data: VarInt,
}

/// The summary of a MAX_STREAM_DATA frame written into a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxStreamDataSummary {
    /// The stream.
    pub stream_id: StreamId,
    /// The limit the frame carried.
    pub maximum_stream_data: VarInt,
}

/// The summary of a MAX_STREAMS frame written into a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaxStreamsSummary {
    /// The streams it limits.
    pub directionality: Directionality,
    /// The limit the frame carried.
    pub maximum_streams: StreamCount,
}

/// The summary of a DATA_BLOCKED frame written into a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataBlockedSummary {
    /// The limit the frame carried.
    pub maximum_data: VarInt,
}

/// The summary of a STREAM_DATA_BLOCKED frame written into a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamDataBlockedSummary {
    /// The stream.
    pub stream_id: StreamId,
    /// The limit the frame carried.
    pub maximum_stream_data: VarInt,
}

/// The summary of a STREAMS_BLOCKED frame written into a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamsBlockedSummary {
    /// The streams it is about.
    pub directionality: Directionality,
    /// The limit the frame carried.
    pub maximum_streams: StreamCount,
}

/// The summary of any frame of the stream set (`StreamSetFrameSummary`), as
/// it goes back to the set when the packet is delivered or lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamSetFrameSummary {
    /// A STREAM frame's.
    Stream(StreamSummary),
    /// A RESET_STREAM frame's.
    ResetStream(ResetStreamSummary),
    /// A STOP_SENDING frame's.
    StopSending(StopSendingSummary),
    /// A MAX_DATA frame's.
    MaxData(MaxDataSummary),
    /// A MAX_STREAM_DATA frame's.
    MaxStreamData(MaxStreamDataSummary),
    /// A MAX_STREAMS frame's.
    MaxStreams(MaxStreamsSummary),
    /// A DATA_BLOCKED frame's.
    DataBlocked(DataBlockedSummary),
    /// A STREAM_DATA_BLOCKED frame's.
    StreamDataBlocked(StreamDataBlockedSummary),
    /// A STREAMS_BLOCKED frame's.
    StreamsBlocked(StreamsBlockedSummary),
}

// ---- the frame sources ----

/// One of the nine kinds of frame sources of the stream set
/// (`StreamFrameKind`): how an item of it is supplied to the set, and how
/// its items and summaries go back to the set.
pub trait StreamFrameKind: FrameSourceKind {
    /// The summary of a frame of the kind, as instants do not matter to it.
    type FrameSummary: Copy;

    /// Give `item` to `set`, which writes the kind's frame into `packet`.
    fn supply<X, Lc, K, Rs, P, W, Q, Idx>(
        set: &mut X,
        publish: &P,
        item: Self::Item<'_>,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        X: StreamSet<Lc, K, Rs>,
        Rs: StreamResets,
        P: StreamIntentHandle<X::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<Self::FrameSummary, Idx>,
        Q: PacketPosition;

    /// The summary as the set takes it back.
    fn set_summary(summary: Self::FrameSummary) -> StreamSetFrameSummary;

    /// The intent `item` stands for.
    fn key(item: Self::Item<'_>) -> StreamIntentKey;
}

/// A frame source of the streams in a lineage `V` (`LineageStreamFrameSource`):
/// it writes the frames of the kind `F` through the stream set `X`, which the
/// lend appended to the lineage, and publishes through the handle `P`. `Lc`,
/// `K` and `Rs` are the set's close cause, ticket and reset kind, `Is` the
/// position of the set in the lineage.
pub struct LineageStreamFrameSource<'l, 'r, V, X, Lc, K, Rs, P, F, Is> {
    lineage: &'l mut Lineage<'r, V>,
    publish: P,
    types: PhantomData<StreamSourceTypes<X, Lc, K, Rs, F, Is>>,
}

/// What [`LineageStreamFrameSource`] takes its components by.
type StreamSourceTypes<X, Lc, K, Rs, F, Is> = fn() -> (X, Lc, K, Rs, F, Is);

impl<V, X, Lc, K, Rs, P, F, Is> core::fmt::Debug
    for LineageStreamFrameSource<'_, '_, V, X, Lc, K, Rs, P, F, Is>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LineageStreamFrameSource")
    }
}

impl<'l, 'r, V, X, Lc, K, Rs, P, F, Is>
    LineageStreamFrameSource<'l, 'r, V, X, Lc, K, Rs, P, F, Is>
{
    fn new(lineage: &'l mut Lineage<'r, V>, publish: P) -> Self {
        Self {
            lineage,
            publish,
            types: PhantomData,
        }
    }
}

/// Without the established layer, nothing is written and nothing taken
/// back: the streams ended with it.
impl<V, X, Lc, K, Rs, P, F, Is> FrameSource
    for LineageStreamFrameSource<'_, '_, V, X, Lc, K, Rs, P, F, Is>
where
    V: GetOptionalAt<X, Is>,
    X: StreamSet<Lc, K, Rs>,
    Rs: StreamResets,
    P: StreamIntentHandle<X::SendParameters, K>,
    K: IntentTicketResize + IntentTicketWithdraw,
    F: StreamFrameKind,
{
    type Summary = F::FrameSummary;
    type Class = InFlightClass;
    type Item<'b> = F::Item<'b>;

    fn supply<W, Q, Idx>(
        &mut self,
        item: F::Item<'_>,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<F::FrameSummary, Idx>,
        Q: PacketPosition,
    {
        match self.lineage.get_optional_mut::<X, Is>() {
            Some(mut set) => F::supply(&mut *set, &self.publish, item, packet),
            None => Supplied::Open(packet),
        }
    }

    fn delivered(&mut self, _: PacketNumberSpaceKind, summary: F::FrameSummary) {
        if let Some(mut set) = self.lineage.get_optional_mut::<X, Is>() {
            set.on_frame_delivered(&self.publish, F::set_summary(summary));
        }
    }

    fn lost(&mut self, _: PacketNumberSpaceKind, summary: &F::FrameSummary) {
        if let Some(mut set) = self.lineage.get_optional_mut::<X, Is>() {
            set.on_frame_lost(&self.publish, F::set_summary(*summary));
        }
    }

    fn unfulfilled(&mut self, item: F::Item<'_>, cause: Unfulfilled) {
        if let Some(mut set) = self.lineage.get_optional_mut::<X, Is>() {
            set.on_intent_unfulfilled(&self.publish, F::key(item), cause);
        }
    }
}

/// The kinds of the stream set's frame sources: their items, summaries and
/// how each is given to the set and found in a lineage.
macro_rules! stream_frame_kinds {
    ($(
        $(#[$doc:meta])*
        $kind:ident {
            item: $item:ty,
            summary: $summary:ident,
            variant: $variant:ident,
            supply: |$set:ident, $publish:ident, $it:pat_param, $packet:ident| $supply:expr,
            key: |$key_item:pat_param| $key:expr,
        }
    )*) => {$(
        $(#[$doc])*
        #[derive(Debug)]
        pub enum $kind {}

        impl FrameSourceKind for $kind {
            type Item<'a> = $item;
            type Summary<I> = $summary;
        }

        impl StreamFrameKind for $kind {
            type FrameSummary = $summary;

            fn supply<X, Lc, K, Rs, P, W, Q, Idx>(
                $set: &mut X,
                $publish: &P,
                $it: $item,
                $packet: OpenPacket<W, InFlightClass, Q>,
            ) -> Supplied<W, InFlightClass, Q>
            where
                X: StreamSet<Lc, K, Rs>,
        Rs: StreamResets,
                P: StreamIntentHandle<X::SendParameters, K>,
                K: IntentTicketResize + IntentTicketWithdraw,
                W: PacketWriting,
                SummaryOf<W>: InjectSummary<$summary, Idx>,
                Q: PacketPosition,
            {
                $supply
            }

            fn set_summary(summary: $summary) -> StreamSetFrameSummary {
                StreamSetFrameSummary::$variant(summary)
            }

            fn key($key_item: $item) -> StreamIntentKey {
                $key
            }
        }

        /// The frames are written by the stream set of the established
        /// layer, which the lend appends to the lineage, and publish
        /// through the handle of the intake in the connection node.
        impl<T, L, V, Ii, Is, Idx> FindFrameSource<T, L, V, (Ii, Is, Idx)> for $kind
        where
            T: Choices,
            L: crate::error::ConnectionErrorsOf + StreamResetsOf,
            SendTypes<T, L>: HostSendStrategyTypes
                + IntakePublishOutcome<StreamIntent<SendParametersOf<T>>, AnyActiveLinkPath>,
            StreamsOf<T, L>: StreamSet<CloseCauseOf<T, L>, StreamIntentTicketOf<T, L>, StreamResetsOfParts<L>, SendParameters = SendParametersOf<T>>,
            StreamIntentTicketOf<T, L>: IntentTicketResize + IntentTicketWithdraw,
            IntakeOf<T, L>: SendIntentIntake<AnyActiveLinkPath>
                + SharedPublishTo<StreamIntent<SendParametersOf<T>>, AnyActiveLinkPath, Idx>,
            StreamIntentHandleOf<T, L, Idx>: StreamIntentHandle<SendParametersOf<T>, StreamIntentTicketOf<T, L>>,
            V: GetAt<SendStrategyIntake<IntakeOf<T, L>>, Ii> + GetOptionalAt<StreamsOf<T, L>, Is>,
        {
            type Source<'l, 'r>
                = LineageStreamFrameSource<
                'l,
                'r,
                V,
                StreamsOf<T, L>,
                CloseCauseOf<T, L>,
                StreamIntentTicketOf<T, L>,
                StreamResetsOfParts<L>,
                StreamIntentHandleOf<T, L, Idx>,
                $kind,
                Is,
            >
            where
                V: 'l,
                'r: 'l;

            fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
                let publish = lineage
                    .get::<SendStrategyIntake<IntakeOf<T, L>>, Ii>()
                    .intake()
                    .handle::<StreamIntent<SendParametersOf<T>>, Idx>();
                LineageStreamFrameSource::new(lineage, publish)
            }
        }
    )*};
}

stream_frame_kinds! {
    /// The STREAM frames of the streams' data and FINs, as a kind of frame
    /// source.
    StreamFrames {
        item: (StreamId, Urgency),
        summary: StreamSummary,
        variant: Stream,
        supply: |set, publish, (stream_id, urgency), packet| set.supply_stream(publish, stream_id, urgency, packet),
        key: |(stream_id, _)| StreamIntentKey::Stream(stream_id),
    }
    /// The streams' reset frames, as a kind of frame source: RESET_STREAM,
    /// or the frame of the reset target the set's reset kind gives, such as
    /// RESET_STREAM_AT.
    ResetStreamFrames {
        item: StreamId,
        summary: ResetStreamSummary,
        variant: ResetStream,
        supply: |set, publish, stream_id, packet| set.supply_reset_stream(publish, stream_id, packet),
        key: |stream_id| StreamIntentKey::ResetStream(stream_id),
    }
    /// The streams' STOP_SENDING frames, as a kind of frame source.
    StopSendingFrames {
        item: StreamId,
        summary: StopSendingSummary,
        variant: StopSending,
        supply: |set, publish, stream_id, packet| set.supply_stop_sending(publish, stream_id, packet),
        key: |stream_id| StreamIntentKey::StopSending(stream_id),
    }
    /// The connection's MAX_DATA frames, as a kind of frame source.
    MaxDataFrames {
        item: (),
        summary: MaxDataSummary,
        variant: MaxData,
        supply: |set, publish, (), packet| set.supply_max_data(publish, packet),
        key: |()| StreamIntentKey::MaxData,
    }
    /// The streams' MAX_STREAM_DATA frames, as a kind of frame source.
    MaxStreamDataFrames {
        item: StreamId,
        summary: MaxStreamDataSummary,
        variant: MaxStreamData,
        supply: |set, publish, stream_id, packet| set.supply_max_stream_data(publish, stream_id, packet),
        key: |stream_id| StreamIntentKey::MaxStreamData(stream_id),
    }
    /// The MAX_STREAMS frames of the peer's streams, as a kind of frame
    /// source.
    MaxStreamsFrames {
        item: Directionality,
        summary: MaxStreamsSummary,
        variant: MaxStreams,
        supply: |set, publish, directionality, packet| set.supply_max_streams(publish, directionality, packet),
        key: |directionality| StreamIntentKey::MaxStreams(directionality),
    }
    /// The connection's DATA_BLOCKED frames, as a kind of frame source.
    DataBlockedFrames {
        item: (),
        summary: DataBlockedSummary,
        variant: DataBlocked,
        supply: |set, publish, (), packet| set.supply_data_blocked(publish, packet),
        key: |()| StreamIntentKey::DataBlocked,
    }
    /// The streams' STREAM_DATA_BLOCKED frames, as a kind of frame source.
    StreamDataBlockedFrames {
        item: StreamId,
        summary: StreamDataBlockedSummary,
        variant: StreamDataBlocked,
        supply: |set, publish, stream_id, packet| set.supply_stream_data_blocked(publish, stream_id, packet),
        key: |stream_id| StreamIntentKey::StreamDataBlocked(stream_id),
    }
    /// The STREAMS_BLOCKED frames of this side's streams, as a kind of
    /// frame source.
    StreamsBlockedFrames {
        item: Directionality,
        summary: StreamsBlockedSummary,
        variant: StreamsBlocked,
        supply: |set, publish, directionality, packet| set.supply_streams_blocked(publish, directionality, packet),
        key: |directionality| StreamIntentKey::StreamsBlocked(directionality),
    }
}

#[cfg(test)]
mod tests;
