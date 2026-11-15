//! The stream ID ledger: which streams of a connection are open, the limits
//! on opening more, and which have been reclaimed.
//!
//! Stream IDs ([RFC 9000 §2.1]) fall into four types, by initiator and by
//! directionality; each type numbers its streams from zero. The ledger keeps
//! for each type how many streams were opened, and the limit on opening
//! more ([RFC 9000 §4.6]): for the streams of this endpoint the limit the
//! peer granted (`initial_max_streams_*`, then `MAX_STREAMS`), for the
//! streams of the peer the limit this endpoint granted. Allocating IDs and
//! opening credit are kept together because opening a stream needs both and
//! `MAX_STREAMS` changes only the credit.
//!
//! - This endpoint opens a stream with [`open_local`](StreamIdLedger::open_local):
//!   the next ID of the type, if the peer's limit allows it.
//! - A frame of the peer that names a stream passes
//!   [`on_receiving_part_frame`](StreamIdLedger::on_receiving_part_frame) or
//!   [`on_sending_part_frame`](StreamIdLedger::on_sending_part_frame) before it
//!   reaches the stream: they check the initiator, the directionality and
//!   the limits ([RFC 9000 §19]), and open peer streams. A stream of the peer
//!   opens every stream of its type with a lower ID ([RFC 9000 §3.2]); only
//!   the stream the frame names is reported as created, the others are
//!   recorded as opened and reported as created when their first frame
//!   arrives.
//! - A stream whose state is no longer needed is reclaimed
//!   ([`reclaim`](StreamIdLedger::reclaim)). Each type keeps its reclaimed
//!   indices as ranges; a late frame for a reclaimed stream is reported so the
//!   caller ignores it instead of opening the stream again. Reclaiming a
//!   stream of the peer lets the limit granted to the peer grow by one
//!   ([`max_streams`](StreamIdLedger::max_streams)).
//! - When a limit keeps this endpoint from opening a stream, a
//!   `STREAMS_BLOCKED` frame is wanted once for that limit
//!   ([`streams_blocked`](StreamIdLedger::streams_blocked)).
//!
//! The ledger holds no locks and no waiters; it is state that one owner
//! changes through `&mut self`.
//!
//! [RFC 9000 §2.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1
//! [RFC 9000 §3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-3.2
//! [RFC 9000 §4.6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6
//! [RFC 9000 §19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19
use crate::blocked_signal::BlockedSignal;
use index_ranges::IndexRanges;
use sakuya_wire::v1::role::Role;
use sakuya_wire::v1::stream_count::StreamCount;
use sakuya_wire::v1::stream_id::{Directionality, Initiator, StreamId};
use sakuya_wire::v1::transport_error::TransportErrorCode;
use snafu::Snafu;

mod index_ranges;

/// The limits on opening streams of each directionality, as the transport
/// parameters `initial_max_streams_bidi` and `initial_max_streams_uni` state
/// them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct InitialMaxStreams {
    /// `initial_max_streams_bidi`: how many bidirectional streams may be
    /// opened.
    pub bidirectional: StreamCount,
    /// `initial_max_streams_uni`: how many unidirectional streams may be
    /// opened.
    pub unidirectional: StreamCount,
}

impl InitialMaxStreams {
    fn get(self, directionality: Directionality) -> StreamCount {
        match directionality {
            Directionality::Bidirectional => self.bidirectional,
            Directionality::Unidirectional => self.unidirectional,
        }
    }
}

/// A frame type that names a stream and is addressed to the receiving part
/// of it: a frame the sending part of the peer sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReceivingPartFrameType {
    /// STREAM.
    Stream,
    /// RESET_STREAM.
    ResetStream,
    /// STREAM_DATA_BLOCKED.
    StreamDataBlocked,
    /// RESET_STREAM_AT, of the reliable stream reset extension.
    #[cfg(feature = "reset_stream_at")]
    ResetStreamAt,
}

/// A frame type that names a stream and is addressed to the sending part of
/// it: a frame the receiving part of the peer sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SendingPartFrameType {
    /// STOP_SENDING.
    StopSending,
    /// MAX_STREAM_DATA.
    MaxStreamData,
}

/// What the stream a frame names is, once the frame passed the checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IdentifiedStream {
    /// A stream of the peer that the frame creates: its parts are to be
    /// built now. Each stream is reported as created once.
    Created,
    /// A stream that was created before and is not reclaimed.
    Existing,
    /// A stream that was reclaimed; the frame is to be ignored.
    Reclaimed,
}

/// The streams of one type that this endpoint opens.
#[derive(Clone, Debug)]
struct LocalStreams {
    /// How many were opened; the next one has this index.
    opened: u64,
    /// The limit the peer granted.
    limit: StreamCount,
    reclaimed: IndexRanges,
    blocked: BlockedSignal<StreamCount>,
}

impl LocalStreams {
    fn new(limit: StreamCount) -> Self {
        Self {
            opened: 0,
            limit,
            reclaimed: IndexRanges::default(),
            blocked: BlockedSignal::default(),
        }
    }
}

/// The streams of one type that the peer opens.
#[derive(Clone, Debug)]
struct PeerStreams {
    /// How many are open, created or not; the indices below it.
    opened: u64,
    /// The highest limit granted to the peer that may be visible to it.
    limit: StreamCount,
    /// The limit granted in the transport parameters.
    initial_limit: StreamCount,
    /// How many were reclaimed.
    reclaimed_count: u64,
    /// The open indices that no frame has named yet.
    uncreated: IndexRanges,
    reclaimed: IndexRanges,
}

impl PeerStreams {
    fn new(limit: StreamCount) -> Self {
        Self {
            opened: 0,
            limit,
            initial_limit: limit,
            reclaimed_count: 0,
            uncreated: IndexRanges::default(),
            reclaimed: IndexRanges::default(),
        }
    }

    /// The limit to grant: the initial one plus one for each reclaimed
    /// stream, at most [`StreamCount::MAX`].
    fn target(&self) -> StreamCount {
        let target = self
            .initial_limit
            .get()
            .saturating_add(self.reclaimed_count)
            .min(StreamCount::MAX.get());
        // invariant: the value is at most `StreamCount::MAX`.
        StreamCount::new(target).unwrap_or(StreamCount::MAX)
    }
}

/// A value for each directionality.
#[derive(Clone, Debug)]
struct ByDirectionality<T> {
    bidirectional: T,
    unidirectional: T,
}

impl<T> ByDirectionality<T> {
    fn new(mut make: impl FnMut(Directionality) -> T) -> Self {
        Self {
            bidirectional: make(Directionality::Bidirectional),
            unidirectional: make(Directionality::Unidirectional),
        }
    }

    fn get(&self, directionality: Directionality) -> &T {
        match directionality {
            Directionality::Bidirectional => &self.bidirectional,
            Directionality::Unidirectional => &self.unidirectional,
        }
    }

    fn get_mut(&mut self, directionality: Directionality) -> &mut T {
        match directionality {
            Directionality::Bidirectional => &mut self.bidirectional,
            Directionality::Unidirectional => &mut self.unidirectional,
        }
    }
}

/// The stream IDs of one connection: allocation and opening credit for both
/// endpoints' streams, and the reclaimed streams.
///
/// See the [module documentation](self).
#[derive(Clone, Debug)]
pub struct StreamIdLedger {
    role: Role,
    local: ByDirectionality<LocalStreams>,
    peer: ByDirectionality<PeerStreams>,
}

impl StreamIdLedger {
    /// Creates the ledger of an endpoint in `role`.
    ///
    /// `granted_by_peer` is the limits of the peer's transport parameters,
    /// on the streams this endpoint opens; `granted_to_peer` is the limits of
    /// this endpoint's transport parameters, on the streams the peer opens.
    pub fn new(
        role: Role,
        granted_by_peer: InitialMaxStreams,
        granted_to_peer: InitialMaxStreams,
    ) -> Self {
        Self {
            role,
            local: ByDirectionality::new(|d| LocalStreams::new(granted_by_peer.get(d))),
            peer: ByDirectionality::new(|d| PeerStreams::new(granted_to_peer.get(d))),
        }
    }

    /// The role of this endpoint.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Opens the next stream of `directionality` of this endpoint and
    /// returns its ID.
    ///
    /// # Errors
    ///
    /// [`MaxStreamsReachedError`] if the peer's limit allows no more streams
    /// of `directionality`; nothing is opened, and a `STREAMS_BLOCKED` frame
    /// is wanted for the limit unless one was sent for it already.
    pub fn open_local(
        &mut self,
        directionality: Directionality,
    ) -> Result<StreamId, MaxStreamsReachedError> {
        let initiator = initiator(self.role);
        let streams = self.local.get_mut(directionality);
        if streams.opened >= streams.limit.get() {
            streams.blocked.on_blocked(streams.limit);
            return Err(MaxStreamsReachedError {
                directionality,
                limit: streams.limit,
            });
        }
        let index = streams.opened;
        // invariant: `index` is below the limit, at most 2^60, so it is a
        // stream index.
        let Ok(id) = StreamId::new(initiator, directionality, index) else {
            unreachable!("an index below a stream count limit is a stream index");
        };
        streams.opened += 1;
        Ok(id)
    }

    /// The limit on streams of `directionality` that this endpoint may open.
    pub fn local_limit(&self, directionality: Directionality) -> StreamCount {
        self.local.get(directionality).limit
    }

    /// How many streams of `directionality` this endpoint has opened.
    pub fn local_opened(&self, directionality: Directionality) -> u64 {
        self.local.get(directionality).opened
    }

    /// Applies a `MAX_STREAMS` frame for streams of `directionality`: the
    /// limit becomes the larger of the current one and `maximum`. Returns
    /// whether it grew.
    ///
    /// A value that does not increase the limit is ignored ([RFC 9000
    /// §19.11](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11)).
    /// Growth clears a `STREAMS_BLOCKED` intent for a lower limit.
    pub fn on_max_streams(&mut self, directionality: Directionality, maximum: StreamCount) -> bool {
        let streams = self.local.get_mut(directionality);
        if maximum <= streams.limit {
            return false;
        }
        streams.limit = maximum;
        streams.blocked.on_limit_raised(maximum);
        true
    }

    /// The limit to send in `STREAMS_BLOCKED` for streams of
    /// `directionality` now, if any.
    pub fn streams_blocked(&self, directionality: Directionality) -> Option<StreamCount> {
        self.local.get(directionality).blocked.wanted()
    }

    /// Records that a `STREAMS_BLOCKED` frame for streams of
    /// `directionality` carrying `limit` was sent; no other is wanted for
    /// that limit.
    pub fn on_streams_blocked_sent(&mut self, directionality: Directionality, limit: StreamCount) {
        self.local.get_mut(directionality).blocked.on_sent(limit);
    }

    /// Checks the stream that a frame addressed to the receiving part names,
    /// and opens it if it is a new stream of the peer.
    ///
    /// # Errors
    ///
    /// [`ReceivingPartFrameError`] if the frame names a stream it must not;
    /// nothing changes then, and the caller must close the connection with
    /// its [`transport_error_code`](ReceivingPartFrameError::transport_error_code).
    pub fn on_receiving_part_frame(
        &mut self,
        stream_id: StreamId,
        frame_type: ReceivingPartFrameType,
    ) -> Result<IdentifiedStream, ReceivingPartFrameError> {
        if self.is_local(stream_id) && stream_id.directionality() == Directionality::Unidirectional
        {
            return Err(SendOnlyStreamError {
                stream_id,
                frame_type,
            }
            .into());
        }
        self.identify(stream_id)
    }

    /// Checks the stream that a frame addressed to the sending part names,
    /// and opens it if it is a new stream of the peer.
    ///
    /// # Errors
    ///
    /// [`SendingPartFrameError`] if the frame names a stream it must not;
    /// nothing changes then, and the caller must close the connection with
    /// its [`transport_error_code`](SendingPartFrameError::transport_error_code).
    pub fn on_sending_part_frame(
        &mut self,
        stream_id: StreamId,
        frame_type: SendingPartFrameType,
    ) -> Result<IdentifiedStream, SendingPartFrameError> {
        if !self.is_local(stream_id) && stream_id.directionality() == Directionality::Unidirectional
        {
            return Err(ReceiveOnlyStreamError {
                stream_id,
                frame_type,
            }
            .into());
        }
        self.identify(stream_id)
    }

    /// Records that the state of `stream_id` is no longer needed. Later
    /// frames for it are reported as [`IdentifiedStream::Reclaimed`]; for a
    /// stream of the peer, the limit to grant grows by one.
    ///
    /// # Errors
    ///
    /// [`ReclaimError`] if the stream is not open, was never created, or was
    /// reclaimed already; nothing changes then.
    pub fn reclaim(&mut self, stream_id: StreamId) -> Result<(), ReclaimError> {
        let index = stream_id.index();
        let directionality = stream_id.directionality();
        if self.is_local(stream_id) {
            let streams = self.local.get_mut(directionality);
            snafu::ensure!(
                index < streams.opened,
                reclaim_error::NotOpenedSnafu { stream_id }
            );
            snafu::ensure!(
                !streams.reclaimed.contains(index),
                reclaim_error::AlreadyReclaimedSnafu { stream_id }
            );
            streams.reclaimed.insert(index);
        } else {
            let streams = self.peer.get_mut(directionality);
            snafu::ensure!(
                index < streams.opened,
                reclaim_error::NotOpenedSnafu { stream_id }
            );
            snafu::ensure!(
                !streams.uncreated.contains(index),
                reclaim_error::NotCreatedSnafu { stream_id }
            );
            snafu::ensure!(
                !streams.reclaimed.contains(index),
                reclaim_error::AlreadyReclaimedSnafu { stream_id }
            );
            streams.reclaimed.insert(index);
            streams.reclaimed_count += 1;
        }
        Ok(())
    }

    /// Whether `stream_id` was reclaimed.
    pub fn is_reclaimed(&self, stream_id: StreamId) -> bool {
        let index = stream_id.index();
        let directionality = stream_id.directionality();
        if self.is_local(stream_id) {
            self.local.get(directionality).reclaimed.contains(index)
        } else {
            self.peer.get(directionality).reclaimed.contains(index)
        }
    }

    /// The limit on streams of `directionality` granted to the peer that may
    /// be visible to it; frames naming streams beyond it are violations.
    pub fn peer_limit(&self, directionality: Directionality) -> StreamCount {
        self.peer.get(directionality).limit
    }

    /// How many streams of `directionality` of the peer are open, created by
    /// a frame or not.
    pub fn peer_opened(&self, directionality: Directionality) -> u64 {
        self.peer.get(directionality).opened
    }

    /// The limit to send in `MAX_STREAMS` for streams of `directionality`
    /// now, if any: the initial limit plus one for each reclaimed stream of
    /// the peer, once it is above [`peer_limit`](Self::peer_limit).
    ///
    /// Querying changes nothing; once a frame carrying it may be visible,
    /// record it with [`raise_peer_limit`](Self::raise_peer_limit).
    pub fn max_streams(&self, directionality: Directionality) -> Option<StreamCount> {
        let streams = self.peer.get(directionality);
        let target = streams.target();
        (target > streams.limit).then_some(target)
    }

    /// Records that a limit of `limit` on streams of `directionality` granted
    /// to the peer may have become visible to it, for example because a
    /// `MAX_STREAMS` frame carrying it can no longer be withdrawn.
    ///
    /// The limit takes the larger of the old value and `limit`; returns
    /// whether it grew.
    pub fn raise_peer_limit(&mut self, directionality: Directionality, limit: StreamCount) -> bool {
        let streams = self.peer.get_mut(directionality);
        let grew = limit > streams.limit;
        streams.limit = streams.limit.max(limit);
        grew
    }

    fn is_local(&self, stream_id: StreamId) -> bool {
        stream_id.initiator() == initiator(self.role)
    }

    /// Looks up a stream whose initiator and directionality suit the frame,
    /// opening it if it is a new stream of the peer.
    fn identify<E>(&mut self, stream_id: StreamId) -> Result<IdentifiedStream, E>
    where
        E: From<LocalStreamNotOpenedError> + From<MaxStreamsExceededError>,
    {
        let index = stream_id.index();
        let directionality = stream_id.directionality();
        if self.is_local(stream_id) {
            let streams = self.local.get(directionality);
            if index >= streams.opened {
                return Err(LocalStreamNotOpenedError { stream_id }.into());
            }
            return Ok(if streams.reclaimed.contains(index) {
                IdentifiedStream::Reclaimed
            } else {
                IdentifiedStream::Existing
            });
        }
        let streams = self.peer.get_mut(directionality);
        if index >= streams.limit.get() {
            return Err(MaxStreamsExceededError {
                stream_id,
                limit: streams.limit,
            }
            .into());
        }
        if index >= streams.opened {
            // The lower streams of the type open with it, uncreated.
            streams.uncreated.insert_range(streams.opened, index);
            streams.opened = index + 1;
            return Ok(IdentifiedStream::Created);
        }
        if streams.uncreated.remove(index) {
            return Ok(IdentifiedStream::Created);
        }
        Ok(if streams.reclaimed.contains(index) {
            IdentifiedStream::Reclaimed
        } else {
            IdentifiedStream::Existing
        })
    }
}

/// The initiator of the streams an endpoint in `role` opens.
fn initiator(role: Role) -> Initiator {
    match role {
        Role::Client => Initiator::Client,
        Role::Server => Initiator::Server,
    }
}

/// [`StreamIdLedger::open_local`] found the peer's limit reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "the peer allows no more than {limit} {directionality:?} streams of this endpoint"
))]
pub struct MaxStreamsReachedError {
    directionality: Directionality,
    limit: StreamCount,
}

impl MaxStreamsReachedError {
    /// The directionality of the stream that could not be opened.
    pub const fn directionality(self) -> Directionality {
        self.directionality
    }

    /// The peer's limit, which this endpoint's streams have reached.
    pub const fn limit(self) -> StreamCount {
        self.limit
    }
}

/// A frame names a stream of this endpoint that this endpoint has not opened
/// (`STREAM_STATE_ERROR`, [RFC 9000 §19.8], [§19.5], [§19.10]).
///
/// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
/// [§19.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5
/// [§19.10]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.10
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("a frame names stream {stream_id} of this endpoint, which it has not opened"))]
pub struct LocalStreamNotOpenedError {
    stream_id: StreamId,
}

impl LocalStreamNotOpenedError {
    /// The stream the frame names.
    pub const fn stream_id(self) -> StreamId {
        self.stream_id
    }
}

/// A frame names a stream of the peer beyond the limit granted to the peer
/// (`STREAM_LIMIT_ERROR`, [RFC 9000 §4.6]).
///
/// [RFC 9000 §4.6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "a frame names stream {stream_id} of the peer, beyond the limit of {limit} streams"
))]
pub struct MaxStreamsExceededError {
    stream_id: StreamId,
    limit: StreamCount,
}

impl MaxStreamsExceededError {
    /// The stream the frame names.
    pub const fn stream_id(self) -> StreamId {
        self.stream_id
    }

    /// The limit granted to the peer, which the stream's index reaches.
    pub const fn limit(self) -> StreamCount {
        self.limit
    }
}

/// A frame addressed to the receiving part names a unidirectional stream of
/// this endpoint, which only sends (`STREAM_STATE_ERROR`, [RFC 9000 §19.4],
/// [§19.8], [§19.13]).
///
/// [RFC 9000 §19.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
/// [§19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
/// [§19.13]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.13
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("a {frame_type:?} frame names stream {stream_id}, which only sends"))]
pub struct SendOnlyStreamError {
    stream_id: StreamId,
    frame_type: ReceivingPartFrameType,
}

impl SendOnlyStreamError {
    /// The stream the frame names.
    pub const fn stream_id(self) -> StreamId {
        self.stream_id
    }

    /// The type of the frame.
    pub const fn frame_type(self) -> ReceivingPartFrameType {
        self.frame_type
    }
}

/// A frame addressed to the sending part names a unidirectional stream of the
/// peer, which only receives (`STREAM_STATE_ERROR`, [RFC 9000 §19.5],
/// [§19.10]).
///
/// [RFC 9000 §19.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5
/// [§19.10]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.10
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("a {frame_type:?} frame names stream {stream_id}, which only receives"))]
pub struct ReceiveOnlyStreamError {
    stream_id: StreamId,
    frame_type: SendingPartFrameType,
}

impl ReceiveOnlyStreamError {
    /// The stream the frame names.
    pub const fn stream_id(self) -> StreamId {
        self.stream_id
    }

    /// The type of the frame.
    pub const fn frame_type(self) -> SendingPartFrameType {
        self.frame_type
    }
}

/// Failures of [`StreamIdLedger::on_receiving_part_frame`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum ReceivingPartFrameError {
    /// The frame names a stream of this endpoint that it has not opened.
    #[snafu(context(false), display("frame for a stream not opened"))]
    LocalStreamNotOpened {
        /// The stream.
        source: LocalStreamNotOpenedError,
    },
    /// The frame names a unidirectional stream of this endpoint.
    #[snafu(context(false), display("receiving-part frame for a send-only stream"))]
    SendOnlyStream {
        /// The stream and the frame type.
        source: SendOnlyStreamError,
    },
    /// The frame names a stream of the peer beyond the limit granted to it.
    #[snafu(context(false), display("frame beyond the stream limit"))]
    MaxStreamsExceeded {
        /// The stream and the limit.
        source: MaxStreamsExceededError,
    },
}

impl ReceivingPartFrameError {
    /// The QUIC transport error code to close the connection with.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::LocalStreamNotOpened { .. } | Self::SendOnlyStream { .. } => {
                TransportErrorCode::STREAM_STATE_ERROR
            }
            Self::MaxStreamsExceeded { .. } => TransportErrorCode::STREAM_LIMIT_ERROR,
        }
    }
}

/// Failures of [`StreamIdLedger::on_sending_part_frame`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum SendingPartFrameError {
    /// The frame names a stream of this endpoint that it has not opened.
    #[snafu(context(false), display("frame for a stream not opened"))]
    LocalStreamNotOpened {
        /// The stream.
        source: LocalStreamNotOpenedError,
    },
    /// The frame names a unidirectional stream of the peer.
    #[snafu(
        context(false),
        display("sending-part frame for a receive-only stream")
    )]
    ReceiveOnlyStream {
        /// The stream and the frame type.
        source: ReceiveOnlyStreamError,
    },
    /// The frame names a stream of the peer beyond the limit granted to it.
    #[snafu(context(false), display("frame beyond the stream limit"))]
    MaxStreamsExceeded {
        /// The stream and the limit.
        source: MaxStreamsExceededError,
    },
}

impl SendingPartFrameError {
    /// The QUIC transport error code to close the connection with.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::LocalStreamNotOpened { .. } | Self::ReceiveOnlyStream { .. } => {
                TransportErrorCode::STREAM_STATE_ERROR
            }
            Self::MaxStreamsExceeded { .. } => TransportErrorCode::STREAM_LIMIT_ERROR,
        }
    }
}

/// Failures of [`StreamIdLedger::reclaim`]; each is a mistake of the caller,
/// not of the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(reclaim_error), visibility(pub(crate)))]
pub enum ReclaimError {
    /// The stream is not open.
    #[snafu(display("stream {stream_id} is not open"))]
    NotOpened {
        /// The stream.
        stream_id: StreamId,
    },
    /// The stream of the peer is open, but no frame has created it.
    #[snafu(display("stream {stream_id} was never created"))]
    NotCreated {
        /// The stream.
        stream_id: StreamId,
    },
    /// The stream was reclaimed already.
    #[snafu(display("stream {stream_id} was reclaimed already"))]
    AlreadyReclaimed {
        /// The stream.
        stream_id: StreamId,
    },
}

#[cfg(test)]
mod tests;
