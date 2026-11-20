//! The streams of a connection in its established layer: the trait of the
//! stream set ([`StreamSet`]), the facts it is made from, the failures of
//! the frames it takes, and how version 1 builds and ends it.
//!
//! The established layer of version 1 holds one stream set, of the kind the
//! host chooses ([`HostChoices::Streams`]). It is made when the layer is
//! built, from the transport parameters of both sides and this side's role
//! ([`StreamSetFacts`]) and from the configuration the connection was made
//! with ([`StreamSetConfig`]); when the layer ends, every stream hears of it
//! ([`StreamSet::layer_ended`]). The dispatch of a packet's frames hands the
//! nine frames of streams and flow control to it (see
//! [`dispatch`](super::dispatch)).
//!
//! Every frame that names a stream passes the checks of the streams'
//! identity before it reaches the part of the stream it concerns: the
//! initiator, the directionality, a stream of this side not opened yet and
//! the limit on the peer's streams. The default stream set is
//! [`OwnedStreamSet`](owned::OwnedStreamSet), which the connection holds
//! and only the capabilities through the shared connection reach;
//! [`LockedStreamSet`](locked::LockedStreamSet) also gives capabilities
//! held apart from the connection.
//!
//! The set also writes the nine frames, through one kind of frame source
//! for each, and keeps the tickets of their intents, which it publishes
//! through the send strategy's publisher, or through an intake of its own
//! that it asks the strategy's core for when it is built ([`send`]).

pub mod locked;
pub mod owned;
pub mod resets;
pub mod send;
mod set_state;

use core::{
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
};
use sakuya_stream::receive::violation::ResetStreamViolation;
use sakuya_wire::v1::frame::write::InFlightClass;

use bytes::{Buf, BufMut, Bytes};
use sakuya_stream::{
    connection::{AbortCause, CloseReason, LayerEnd, LayerEndedError},
    receive::{
        read::ReadError,
        stop::StopError,
        violation::{OnResetStreamError, OnStreamFrameError},
    },
    send::{
        finish::{CloseError, ResetError},
        write::{FlushError, WriteError, WriteReport},
    },
    send_options::{
        destination::{AnyActiveLinkPath, Unfulfilled},
        urgency::Urgency,
    },
    stream_id_ledger::{ReceivingPartFrameError, SendingPartFrameError},
};
use sakuya_wire::{
    parameters::ParametersOf,
    parts::Selector,
    v1::{
        application_error::ApplicationErrorCode,
        encryption_level::EncryptionLevel,
        frame::{
            data_blocked::DataBlockedFrame, max_data::MaxDataFrame,
            max_stream_data::MaxStreamDataFrame, max_streams::MaxStreamsFrame,
            reset_stream::ResetStreamFrame, stop_sending::StopSendingFrame, stream::StreamFrame,
            stream_data_blocked::StreamDataBlockedFrame, streams_blocked::StreamsBlockedFrame,
        },
        role::Role,
        stream_id::{Directionality, StreamId},
        transport_error::TransportErrorCode,
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace,
            integer::{
                InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
                InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni,
            },
        },
    },
};
use snafu::Snafu;

use self::resets::{PeerResetSupportFrom, StreamResets, StreamResetsOf, StreamResetsOfParts};
use self::send::{
    DataBlockedSummary, MaxDataSummary, MaxStreamDataSummary, MaxStreamsSummary,
    ResetStreamSummary, StopSendingSummary, StreamDataBlockedSummary, StreamIntent,
    StreamIntentKey, StreamSetFrameSummary, StreamSummary, StreamsBlockedSummary,
};
use super::{
    Choices, CloseCauseOf, ConnectionArgs, Side,
    application_handles::{
        connection::ConnectionHandleStateOf, established_layer::TryOpenStreamError,
        stream::AllAcknowledgedError,
    },
    close::CloseReasonRecord,
    component_events::PeerTransportParametersKnown,
    events::{ConnectionEventSink, ConnectionEvents, SharedEvents},
    own_args,
    parameters::{LocalTransportParameters, PeerTransportParameters},
    send::SendTypes,
    send_planning::{
        ComponentIntake, ComponentPublishing, HostSendStrategyTypes, PublisherOf, SendStrategyCore,
        SendStrategyOf, SendStrategyPublisher, StrategyPublisherFor, StrategyPublisherForTicket,
        StrategyPublisherOf,
    },
};
use crate::v1::{
    EventsOf, HostChoices, SendParametersOf, SharedEventsOf, StreamSetConfigOf, StreamSetFamilyOf,
};
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, RequestOf,
    },
    component_event::{EventSubscriptions, TriggeredEvents},
    error::ConnectionErrorsOf,
    feedback::InjectSummary,
    layer::{self, EstablishedEnd},
    others::OtherNodes,
    share::{ConnectionArgsOf, LineageLists, LineagePartList},
    take::{GetAt, Take, TakeEach},
    write::{OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// A kind of stream set: one stream set type for each `Lc`, `I`, `X` and `E`
/// ([`StreamSet`]), which all take the same configuration and send with the
/// same parameters. The host chooses the kind
/// ([`HostChoices::Streams`]); the connection
/// gives the four types, which follow from the list of parts.
pub trait StreamSetFamily: 'static {
    /// What the composition configures the stream set with; the connection
    /// node keeps it from the connection's making until the established
    /// layer is built.
    type Config: Clone + Default + 'static;
    /// The parameters application data is sent with.
    type SendParameters: Clone + PartialEq + Default + 'static;
    /// The stream set for `Lc`, this endpoint's reason for closing, `I`,
    /// the send strategy types its intents are published to, which give
    /// what the set publishes through and the ticket it keeps for a stream
    /// intent ([`ComponentPublishing`]), `X`, how the streams are reset,
    /// and `E`, the handle the events of the streams are given through
    /// ([`ConnectionEvents::Shared`]); a set that gives no events may drop
    /// it. Version 1 asks for it to be a [`StreamSet`] where it uses it.
    type Set<Lc, I: HostSendStrategyTypes, X: StreamResets, E: SharedEvents + Clone + 'static>
    where
        Self: ComponentPublishing<I, StreamIntent<Self::SendParameters>>;
}

/// The set of a connection's streams in its established layer.
///
/// `Lc` is the type of this endpoint's reason for closing the connection,
/// which the errors of the streams carry, and `I` the send strategy types
/// its intents are published to; `X` is how its streams are reset
/// ([`resets`]), which also gives the
/// failure of a RESET_STREAM frame. The driver hands it the frames of
/// streams and flow control, one method for each of the nine frames, and
/// the end of the layer; the application opens and accepts streams through
/// its [`Handle`](Self::Handle).
///
/// A frame that names a stream passes the checks of the streams' identity
/// before it reaches the part of the stream it concerns. A frame that fails
/// returns a [`StreamSetFrameErrorOf`], and the connection closes: the frames
/// after it in the packet are not handed over, and what the failed frame
/// changed is not undone.
///
/// The set also writes the nine frames: each of its frame sources
/// ([`send`]) gives it the item planned, with the strategy's publisher,
/// and takes back the summaries of the frames written once their packets
/// are delivered or lost. Every method that may change what is to be sent
/// is lent the publisher, `publish`, and leaves the intents matching what
/// is due afterwards. A set that publishes through an intake of its own,
/// asked for when it is built ([`Intake`](Self::Intake)), publishes through
/// that instead, and leaves the publisher as it is; whoever lent the
/// publisher hands on what changed there either way.
pub trait StreamSet<Lc, I: HostSendStrategyTypes, X: StreamResets>: Sized {
    /// What the set gives that can be held apart from it: the capabilities
    /// of a set that has one, lent the set from the established layer's
    /// handle, take it to open and accept streams.
    type Handle: Clone;

    /// What the composition configures the stream set with; the connection
    /// node keeps it from the connection's making until the established
    /// layer is built. Its default is what a composition that sets nothing
    /// gets.
    type Config: Clone + Default;

    /// The parameters application data is sent with: what the stream
    /// intents of the data carry.
    type SendParameters;

    /// The handle the set gives the events of its streams through: the
    /// connection's ([`ConnectionEvents::Shared`]).
    type Events;

    /// What the set publishes through apart from the publisher it is lent,
    /// got from the strategy's core when the set is built
    /// ([`ComponentIntake`]): `()` for a set that publishes through the
    /// publisher.
    type Intake;

    /// The reason the termination policy of a sending part gives for a
    /// write limit ([`WriteError`]).
    type WriteLimitReason;

    /// The reason the termination policy of a receiving part gives for a
    /// receive buffer it destroyed ([`ReadError`]).
    type ReceiveTerminationReason;

    /// A block a read of a receiving part gives
    /// ([`poll_read_chunk`](Self::poll_read_chunk)).
    type Chunk: Buf;

    /// The stream set of an established layer, from the facts of the
    /// connection, with what the peer allows the resets of the kind `X`,
    /// the configuration, the handle for the events of its streams, and
    /// what it publishes through apart from the publisher.
    fn new(
        facts: StreamSetFacts<X::PeerSupport>,
        config: Self::Config,
        events: Self::Events,
        intake: Self::Intake,
    ) -> Self;

    /// A handle for the application.
    fn handle(&self) -> Self::Handle;

    /// Takes a STREAM frame, which arrived in a packet protected at `level`.
    ///
    /// # Errors
    ///
    /// [`StreamSetFrameErrorOf`] if the frame breaks a rule of streams or flow
    /// control; the connection closes.
    fn on_stream_frame<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        level: EncryptionLevel,
        frame: StreamFrame<Bytes>,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Takes a RESET_STREAM frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_reset_stream<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: ResetStreamFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Takes a reset frame of the reset kind besides RESET_STREAM
    /// ([`StreamResets::ResetFrame`]): it passes the checks of the streams'
    /// identity as RESET_STREAM does, and goes to the stream's receiving
    /// part ([`StreamResets::on_reset_frame`]). A part that adds the frame
    /// dispatches it here; RFC 9000's resets have none.
    ///
    /// # Errors
    ///
    /// As [`on_reset_stream`](Self::on_reset_stream).
    fn on_reset_frame<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: X::ResetFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Takes a STOP_SENDING frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_stop_sending<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: StopSendingFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Takes a MAX_DATA frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_max_data<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: MaxDataFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Takes a MAX_STREAM_DATA frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_max_stream_data<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: MaxStreamDataFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Takes a MAX_STREAMS frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_max_streams<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: MaxStreamsFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Takes a DATA_BLOCKED frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_data_blocked<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: DataBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Takes a STREAM_DATA_BLOCKED frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_stream_data_blocked<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: StreamDataBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Takes a STREAMS_BLOCKED frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_streams_blocked<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: StreamsBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// The peer's transport parameters of this handshake are known, and
    /// grant `granted_by_peer` in place of those the set was made on, as a
    /// client's early layer is made on the remembered ones (RFC 9000
    /// §7.4.1): the connection's send credit, the limit of each sending
    /// part made so far and the limits on the streams this side opens grow
    /// to theirs, and a stream made after gets its limit from them. A limit
    /// does not shrink: a server that accepts 0-RTT lowers none, which the
    /// handshake checks, and a set made on the known parameters gets the
    /// same again.
    ///
    /// What the peer allows the resets of the set, `peer_reset_support`,
    /// takes the place of what it allowed when the set was made, for every
    /// reset from then on: a peer that announces `reset_stream_at` only in
    /// this handshake allows RESET_STREAM_AT once it is known. A server
    /// that accepts 0-RTT keeps one remembered, which the handshake checks
    /// (draft-ietf-quic-reliable-stream-reset §3). Nothing once the layer
    /// ended.
    fn peer_transport_parameters_known<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        granted_by_peer: FlowControlParameters,
        peer_reset_support: X::PeerSupport,
    ) where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// The established layer ended as `end`: every stream hears of it, the
    /// intents of the set are withdrawn, and every later operation on the
    /// set reports it. The connection may go on, as when the server
    /// rejected 0-RTT, and a layer built anew publishes its own.
    fn layer_ended<Ij, Kp>(&mut self, publish: &mut StrategyPublisherOf<I>, end: LayerEnd<Lc>)
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// The driver panicked, and the layer ended as `end`; it is told instead
    /// of [`layer_ended`](Self::layer_ended), which is never called then.
    ///
    /// It only marks the end, where every operation of the application on
    /// the set, its writers and its readers looks first, and wakes
    /// everything waiting to open, accept, write or read. It does not touch
    /// the streams' state machines or the intents' tickets, as it may run
    /// while the panic unwinds, where a second panic aborts the process;
    /// it takes its locks whatever a holder that panicked left of them.
    fn driver_panicked(&mut self, end: LayerEnd<Lc>);

    /// Opens the next stream of `directionality` of this side for holders
    /// through the shared connection, which find its parts by its ID: the
    /// set keeps each part for its holder until the holder's credential
    /// comes back ([`reclaim_writer`](Self::reclaim_writer),
    /// [`reclaim_reader`](Self::reclaim_reader)), with its last result once
    /// the stream was reclaimed, which does not wait for the credentials
    /// (RFC 9000 §4.6 counts the stream's state, not its holders). At the
    /// peer's limit it
    /// keeps `waker`, if one is given, until the limit may have grown, and
    /// has the peer told that this side is blocked (STREAMS_BLOCKED,
    /// RFC 9000 §4.6).
    ///
    /// # Errors
    ///
    /// [`TryOpenStreamError::AtLimit`] at the limit,
    /// [`TryOpenStreamError::LayerEnded`] once the layer ended.
    fn open_held<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        directionality: Directionality,
        waker: Option<&Waker>,
    ) -> Result<StreamId, TryOpenStreamError<Lc>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// The next stream of `directionality` the peer opened, in the order
    /// their first frames arrived, its parts kept for their holders as
    /// [`open_held`](Self::open_held) keeps them; `Pending` with the waker
    /// of `cx` kept while none is there.
    ///
    /// # Errors
    ///
    /// [`LayerEndedError`] once the layer ended.
    fn poll_accept_held(
        &mut self,
        cx: &mut Context<'_>,
        directionality: Directionality,
    ) -> Poll<Result<StreamId, LayerEndedError<Lc>>>;

    /// The holder of the sending part `credential` names gave it back:
    /// the stream's writer is abandoned, as dropping a writer abandons it,
    /// and the part is reclaimed once it is done. Nothing once the part is
    /// not there.
    fn reclaim_writer<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        credential: StreamWriterCredential,
    ) where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// The holder of the receiving part `credential` names gave it back:
    /// the stream's reader is dropped, and the part is reclaimed once it is
    /// done, as [`reclaim_writer`](Self::reclaim_writer) does the sending
    /// part.
    fn reclaim_reader<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        credential: StreamReaderCredential,
    ) where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Writes from `input` into the sending part of `held`, with the
    /// parameters `parameters` for `destination`, as
    /// [`StreamWrite::poll_write_with`] does; `Pending` with the waker of
    /// `cx` kept while the stream's limit, its policy or the connection's
    /// credit holds it back.
    ///
    /// # Errors
    ///
    /// As [`StreamWrite::poll_write_with`]; once the credential of `held`
    /// came back, the end of a layer whose end is not known.
    ///
    /// [`StreamWrite::poll_write_with`]: super::application_handles::stream::StreamWrite::poll_write_with
    #[allow(clippy::too_many_arguments)] // the write's own, and the publisher
    #[allow(clippy::type_complexity)] // the write's result
    fn poll_write<Ij, Kp, B: Buf + ?Sized>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamWriterCredential,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &Self::SendParameters,
        destination: &AnyActiveLinkPath,
    ) -> Poll<Result<WriteReport, WriteError<Self::WriteLimitReason, Lc>>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Closes the sending part of `held`.
    ///
    /// # Errors
    ///
    /// As [`StreamWrite::close`](super::application_handles::stream::StreamWrite::close),
    /// and as [`poll_write`](Self::poll_write) for a credential that came
    /// back.
    fn close<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamWriterCredential,
    ) -> Result<(), CloseError<Lc>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Resets the sending part of `held` with `code`.
    ///
    /// # Errors
    ///
    /// As [`StreamWrite::reset`](super::application_handles::stream::StreamWrite::reset),
    /// and as [`poll_write`](Self::poll_write) for a credential that came
    /// back.
    fn reset<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamWriterCredential,
        code: ApplicationErrorCode,
    ) -> Result<(), ResetError<Lc>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Resets the sending part of `held` as `request` asks, a request of
    /// the reset kind ([`StreamResets::ResetRequest`]), with what the
    /// peer's parameters allow: those of this handshake once they are
    /// known ([`peer_transport_parameters_known`](Self::peer_transport_parameters_known)).
    ///
    /// # Errors
    ///
    /// As [`StreamResets::reset_with`], and as [`reset`](Self::reset) for a
    /// credential that came back.
    fn reset_with<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamWriterCredential,
        request: X::ResetRequest,
    ) -> Result<(), X::ResetRequestError<Lc>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Whether what was written into the sending part of `held` is handed
    /// to the transport; `Pending` with the waker of `cx` kept while it is
    /// not. It changes no intent.
    ///
    /// # Errors
    ///
    /// As [`StreamWrite::flush`](super::application_handles::stream::StreamWrite::flush),
    /// and as [`poll_write`](Self::poll_write) for a credential that came
    /// back.
    fn poll_flushed(
        &mut self,
        held: &StreamWriterCredential,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), FlushError<Lc>>>;

    /// Whether every byte and the FIN of the sending part of `held` were
    /// acknowledged; `Pending` with the waker of `cx` kept while they are
    /// not. It changes no intent.
    ///
    /// # Errors
    ///
    /// As [`StreamWrite::all_acknowledged`](super::application_handles::stream::StreamWrite::all_acknowledged),
    /// and as [`poll_write`](Self::poll_write) for a credential that came
    /// back.
    fn poll_all_acknowledged(
        &mut self,
        held: &StreamWriterCredential,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), AllAcknowledgedError<Lc>>>;

    /// Reads from the receiving part of `held` into `destination`; `Ok(0)`
    /// at the end of the stream or for no room, as nitori_io's `Read` has
    /// it, and `Pending` with the waker of `cx` kept while nothing is there
    /// to read. What it reads may raise the limits the peer is given.
    ///
    /// # Errors
    ///
    /// The receiving part's [`ReadError`]; once the credential of `held`
    /// came back, the end of a layer whose end is not known.
    #[allow(clippy::type_complexity)] // the read's result
    fn poll_read_into<Ij, Kp, O: BufMut + ?Sized>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamReaderCredential,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, ReadError<Self::ReceiveTerminationReason, Lc, X::Remote>>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Reads a block of at most `maximum` bytes from the receiving part of
    /// `held`; `None` at the end of the stream, and otherwise as
    /// [`poll_read_into`](Self::poll_read_into).
    ///
    /// # Errors
    ///
    /// As [`poll_read_into`](Self::poll_read_into).
    #[allow(clippy::type_complexity)] // the read's result
    fn poll_read_chunk<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamReaderCredential,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<Self::Chunk>, ReadError<Self::ReceiveTerminationReason, Lc, X::Remote>>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Asks the peer to stop sending on the receiving part of `held`, with
    /// `code`.
    ///
    /// # Errors
    ///
    /// As [`StreamRead::stop`](super::application_handles::stream::StreamRead::stop),
    /// and as [`poll_read_into`](Self::poll_read_into) for a credential
    /// that came back.
    fn stop<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamReaderCredential,
        code: ApplicationErrorCode,
    ) -> Result<(), StopError<Lc>>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// Whether a STREAM frame of the receiving part of `held` arrived in a
    /// 0-RTT packet and was taken (RFC 9001 §9.2); `false` once the
    /// credential of `held` came back.
    fn received_zero_rtt(&self, held: &StreamReaderCredential) -> bool;

    /// Writes STREAM frames of the stream `stream_id`: its data, its FIN,
    /// matching the planned urgency and send parameters, and first exposes
    /// what they use before it returns.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_stream<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        urgency: Urgency,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamSummary, Idx>,
        Q: PacketPosition;

    /// Writes the RESET_STREAM frame of the stream `stream_id`, as its
    /// end is now, and first exposes its final size before it returns.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_reset_stream<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<ResetStreamSummary, Idx>,
        Q: PacketPosition;

    /// Writes the STOP_SENDING frame of the stream `stream_id`.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_stop_sending<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StopSendingSummary, Idx>,
        Q: PacketPosition;

    /// Writes the MAX_DATA frame of the connection's limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_max_data<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxDataSummary, Idx>,
        Q: PacketPosition;

    /// Writes the MAX_STREAM_DATA frame of the stream `stream_id`'s limit
    /// now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_max_stream_data<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamDataSummary, Idx>,
        Q: PacketPosition;

    /// Writes the MAX_STREAMS frame of the peer's streams of
    /// `directionality`, with their limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_max_streams<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        directionality: Directionality,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamsSummary, Idx>,
        Q: PacketPosition;

    /// Writes the DATA_BLOCKED frame of the connection's limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_data_blocked<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DataBlockedSummary, Idx>,
        Q: PacketPosition;

    /// Writes the STREAM_DATA_BLOCKED frame of the stream `stream_id`'s
    /// limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_stream_data_blocked<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamDataBlockedSummary, Idx>,
        Q: PacketPosition;

    /// Writes the STREAMS_BLOCKED frame of this side's streams of
    /// `directionality`, with their limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_streams_blocked<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        directionality: Directionality,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamsBlockedSummary, Idx>,
        Q: PacketPosition;

    /// The packet a frame of `summary` was written into was acknowledged.
    fn on_frame_delivered<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        summary: StreamSetFrameSummary,
    ) where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// The packet a frame of `summary` was written into was declared lost,
    /// or its send result is unknown, or its link path ended before it was
    /// settled. A later acknowledgment of it may still come.
    fn on_frame_lost<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        summary: StreamSetFrameSummary,
    ) where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;

    /// The intent of `key` was not fulfilled for `cause`.
    fn on_intent_unfulfilled<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        key: StreamIntentKey,
        cause: Unfulfilled,
    ) where
        StrategyPublisherOf<I>:
            StrategyPublisherForTicket<StreamIntent<Self::SendParameters>, Ij, Kp>;
}

/// The credential of a stream's writer (`StreamWriterCredential`): that
/// the sending part of the stream it names is still held. The stream set's
/// opening and accepting through the shared connection, and the locked
/// set, make it; nothing outside this crate can, but tests with the
/// feature `test-util`. It cannot be cloned: its
/// holder hands it back to the set ([`StreamSet::reclaim_writer`]) once,
/// and lends it to the set ([`StreamSet::poll_write`] and the others) to
/// name the part it holds.
#[derive(Debug)]
pub struct StreamWriterCredential {
    stream_id: StreamId,
}

impl StreamWriterCredential {
    test_util_pub! {
        /// The credential of the writer of `stream_id` just given out.
        ///
        /// Public only for tests: with the feature `test-util`.
        pub fn new(stream_id: StreamId) -> Self {
            Self { stream_id }
        }
    }

    /// The stream's ID.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
}

/// The credential of a stream's reader (`StreamReaderCredential`): that
/// the receiving part of the stream it names is still held, as
/// [`StreamWriterCredential`] is of a sending part; its holder hands it
/// back through [`StreamSet::reclaim_reader`].
#[derive(Debug)]
pub struct StreamReaderCredential {
    stream_id: StreamId,
}

impl StreamReaderCredential {
    test_util_pub! {
        /// The credential of the reader of `stream_id` just given out.
        ///
        /// Public only for tests: with the feature `test-util`.
        pub fn new(stream_id: StreamId) -> Self {
            Self { stream_id }
        }
    }

    /// The stream's ID.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
}

/// What an operation on `id` through the shared connection gets once the
/// part it names is gone, or, with `None`, once the capability's credential
/// is: the end of a layer whose end is not known.
pub(crate) fn held_part_gone<Lc>(id: Option<StreamId>) -> LayerEndedError<Lc> {
    // invariant: a held part stays in its table, or in the table of the
    // held parts, until its credential comes back, and no operation names
    // it after that, as it borrows the credential; a capability's
    // credential leaves it only when it is dropped or turned into another
    debug_assert!(false, "the held part of {id:?} is gone");
    LayerEndedError::new(LayerEnd::ConnectionClosed(CloseReason::Aborted(
        AbortCause::DriverDropped,
    )))
}

/// What a stream set is made from that the connection knows: this side's
/// role, the flow control transport parameters of both sides, and what the
/// peer's parameters allow the resets the set sends, `S`
/// ([`StreamResets::PeerSupport`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSetFacts<S = ()> {
    /// The role of this side.
    pub role: Role,
    /// This side's transport parameters: the limits it grants the peer,
    /// which set how much the streams receive.
    pub granted_to_peer: FlowControlParameters,
    /// The peer's transport parameters: the limits the peer grants this
    /// side, which set how much the streams send.
    pub granted_by_peer: FlowControlParameters,
    /// What the peer's transport parameters allow the resets this side
    /// sends; RFC 9000's resets need nothing (`()`).
    pub peer_reset_support: S,
}

/// The transport parameters of one side that limit the streams and their
/// data (RFC 9000 §4, §18.2); an absent one is 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowControlParameters {
    /// `initial_max_data`: the connection's data.
    pub initial_max_data: InitialMaxData,
    /// `initial_max_stream_data_bidi_local`: the data of a bidirectional
    /// stream the side that sends the parameters opens.
    pub initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal,
    /// `initial_max_stream_data_bidi_remote`: the data of a bidirectional
    /// stream the other side opens.
    pub initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote,
    /// `initial_max_stream_data_uni`: the data of a unidirectional stream
    /// the other side opens.
    pub initial_max_stream_data_uni: InitialMaxStreamDataUni,
    /// `initial_max_streams_bidi`: how many bidirectional streams the other
    /// side may open.
    pub initial_max_streams_bidi: InitialMaxStreamsBidi,
    /// `initial_max_streams_uni`: how many unidirectional streams the other
    /// side may open.
    pub initial_max_streams_uni: InitialMaxStreamsUni,
}

/// Transport parameter slots that hold the six parameters of
/// [`FlowControlParameters`]; `Is` is where each one is.
pub trait FlowControlParameterSlots<Is> {
    /// The six parameters, each 0 when absent.
    fn flow_control_parameters(&self) -> FlowControlParameters;
}

impl<S, Id, Ibl, Ibr, Iu, Isb, Isu> FlowControlParameterSlots<(Id, Ibl, Ibr, Iu, Isb, Isu)> for S
where
    S: Selector<Option<InitialMaxData>, Id>
        + Selector<Option<InitialMaxStreamDataBidiLocal>, Ibl>
        + Selector<Option<InitialMaxStreamDataBidiRemote>, Ibr>
        + Selector<Option<InitialMaxStreamDataUni>, Iu>
        + Selector<Option<InitialMaxStreamsBidi>, Isb>
        + Selector<Option<InitialMaxStreamsUni>, Isu>,
{
    fn flow_control_parameters(&self) -> FlowControlParameters {
        FlowControlParameters {
            initial_max_data: Selector::<Option<InitialMaxData>, Id>::get(self).unwrap_or_default(),
            initial_max_stream_data_bidi_local: Selector::<
                Option<InitialMaxStreamDataBidiLocal>,
                Ibl,
            >::get(self)
            .unwrap_or_default(),
            initial_max_stream_data_bidi_remote: Selector::<
                Option<InitialMaxStreamDataBidiRemote>,
                Ibr,
            >::get(self)
            .unwrap_or_default(),
            initial_max_stream_data_uni: Selector::<Option<InitialMaxStreamDataUni>, Iu>::get(self)
                .unwrap_or_default(),
            initial_max_streams_bidi: Selector::<Option<InitialMaxStreamsBidi>, Isb>::get(self)
                .unwrap_or_default(),
            initial_max_streams_uni: Selector::<Option<InitialMaxStreamsUni>, Isu>::get(self)
                .unwrap_or_default(),
        }
    }
}

/// A frame the stream set took broke a rule of streams or flow control; the
/// connection closes with the transport error code
/// [`transport_error_code`](Self::transport_error_code) gives.
///
/// `R` is the failure of a RESET_STREAM frame, which the reset kind of the
/// composition gives ([`StreamResets::OnResetStreamError`]); by default
/// that of RFC 9000.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum StreamSetFrameError<R = OnResetStreamError> {
    /// A STREAM, RESET_STREAM or STREAM_DATA_BLOCKED frame names a stream
    /// that has no receiving part for it, or one beyond the limit on the
    /// peer's streams (RFC 9000 §19.4, §19.8, §19.13, §4.6).
    #[snafu(display("frame for a receiving part names a stream it must not"))]
    ReceivingPartFrame {
        /// The failed check.
        source: ReceivingPartFrameError,
    },
    /// A STOP_SENDING or MAX_STREAM_DATA frame names a stream that has no
    /// sending part for it, or one beyond the limit on the peer's streams
    /// (RFC 9000 §19.5, §19.10, §4.6).
    #[snafu(display("frame for a sending part names a stream it must not"))]
    SendingPartFrame {
        /// The failed check.
        source: SendingPartFrameError,
    },
    /// The receiving part of the stream rejected a STREAM frame: it breaks
    /// a rule of final sizes or of flow control, of the stream or of the
    /// connection (RFC 9000 §4.1, §4.5).
    #[snafu(display("STREAM frame rejected"))]
    Stream {
        /// The broken rule.
        source: OnStreamFrameError,
    },
    /// The receiving part of the stream rejected a reset frame: it breaks a
    /// rule of final sizes or of flow control (RFC 9000 §4.1, §4.5), or one
    /// of the reset kind, as the reliable stream reset extension's rule on
    /// error codes. The frame is RESET_STREAM, or the reset kind's own frame
    /// taken through the part that defines it (RESET_STREAM_AT).
    #[snafu(display("reset frame rejected"))]
    ResetStream {
        /// The broken rule.
        source: R,
    },
}

/// The failure of a frame a stream set of the reset kind `X` took.
pub type StreamSetFrameErrorOf<X> = StreamSetFrameError<<X as StreamResets>::OnResetStreamError>;

impl<R: ResetStreamViolation> StreamSetFrameError<R> {
    /// The QUIC transport error code to close the connection with.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::ReceivingPartFrame { source } => source.transport_error_code(),
            Self::SendingPartFrame { source } => source.transport_error_code(),
            Self::Stream { source } => source.transport_error_code(),
            Self::ResetStream { source } => source.transport_error_code(),
        }
    }
}

/// The stream set of the choices `T` and the list of parts `L`, which
/// publishes its intents to the send strategy of their send strategy types.
pub type StreamsOf<T, L> = <StreamSetFamilyOf<T> as StreamSetFamily>::Set<
    CloseCauseOf<T, L>,
    SendTypes<T, L>,
    StreamResetsOfParts<L>,
    SharedEventsOf<T, L>,
>;

/// The configuration of the stream set, `C`, kept in the connection node
/// until the established layer is built.
#[derive(Debug)]
pub struct StreamSetConfig<C>(pub C);

/// The connection keeps the configuration it was made with.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for StreamSetConfig<StreamSetConfigOf<T>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        StreamSetConfig(own_args::<T, L, I>(args).stream_set.clone())
    }
}
/// It has no deadline and subscribes to nothing; the stream set is made from it.
impl<C> PassiveDataComponent for StreamSetConfig<C> {}

/// Where the stream set is among the established layer's components.
#[derive(Debug)]
pub struct ChosenStreamSet;

/// The stream set is made when the established layer is built: from this
/// side's role, this side's transport parameters as sent and the peer's as
/// received, and the configuration the connection node keeps.
///
/// Version 1 asks for the layer once both are there
/// ([`EstablishedLayerChange::Ready`](super::advancing::EstablishedLayerChange::Ready)). A
/// layer another part asks for before takes this side's parameters as
/// configured, and the peer's as absent: no stream and no data.
///
/// What the peer allows the resets of the composition is taken from its
/// parameters as received, as the peer's flow control parameters are
/// ([`PeerResetSupportFrom`]); absent, what a peer whose parameters are not
/// known allows. A client's early layer takes it from the remembered ones,
/// until those of this handshake are known (see the set's
/// [`DataComponent`]).
///
/// The set gives the events of its streams through the handle of the
/// connection's event receiver ([`ConnectionEvents::shared`]), and asks the
/// core of the send strategy for what it publishes through apart from the
/// publisher ([`ComponentIntake`]), `Ij` being the place of the stream
/// intents in the sum of intents.
///
/// When the layer ends, every stream hears how it ended, rejected or for
/// the reason in the record of why the connection closed,
/// and the set withdraws its intents through the send strategy's
/// publisher, `In`, lent it there; what changed there is handed on at the
/// connection.
///
/// The state of the connection handle in the connection node hears that
/// the layer was built, so that it gives the layer's handle, and the
/// layer's end when it ends.
impl<T, L, X, Il, Ip, Ic, Ir, Ih, Iev, Isc, In, Jl, Jp, Jr, Ij>
    Build<
        T,
        L,
        layer::Established,
        (ChosenStreamSet, (Il, Ip, Ic, Ir, Ih, Iev, Isc, In), (Jl, Jp, Jr, Ij)),
    > for X
where
    T: Choices<
        Host: HostChoices<
            T,
            Streams: StreamSetFamily<
                Set<
                    CloseCauseOf<T, L>,
                    SendTypes<T, L>,
                    StreamResetsOfParts<L>,
                    SharedEventsOf<T, L>,
                > = X,
            >,
        >,
    >,
    L: LineagePartList<T>
        + ConnectionErrorsOf
        + StreamResetsOf
        + ParametersOf<TransportParameterSpace>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentIntake<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>, Ij>,
    X: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            Config = StreamSetConfigOf<T>,
            SendParameters = SendParametersOf<T>,
            Events = SharedEventsOf<T, L>,
            Intake = <StreamSetFamilyOf<T> as ComponentPublishing<
                SendTypes<T, L>,
                StreamIntent<SendParametersOf<T>>,
            >>::Intake,
        >,
    PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, Ij>,
    TransportParameterSlots: FlowControlParameterSlots<Jl>,
    TransportParameterSlots<L>: FlowControlParameterSlots<Jp>,
    StreamResetsOfParts<L>: PeerResetSupportFrom<TransportParameterSlots<L>, Jr>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<LocalTransportParameters<crate::v1::Part>, Il>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>
        + GetAt<StreamSetConfig<StreamSetConfigOf<T>>, Ic>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<ConnectionHandleStateOf<T, L>, Ih>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>
        + GetAt<SendStrategyCore<SendStrategyOf<T, L>>, Isc>
        + GetAt<SendStrategyPublisher<PublisherOf<T, L>>, In>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::Established>,
        _: &mut ArgsOf<T, L, layer::Established>,
    ) -> Self {
        let granted_to_peer =
            match parents.get::<LocalTransportParameters<crate::v1::Part>, Il>() {
                LocalTransportParameters::Sent(sent) => sent,
                LocalTransportParameters::Configured(configured) => configured,
            }
            .flow_control_parameters();
        // a client's early layer runs on the remembered parameters, as
        // 0-RTT keeps to them (RFC 9000 §7.4.1)
        let peer = parents
            .get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>()
            .slots();
        let granted_by_peer = peer
            .map(FlowControlParameterSlots::flow_control_parameters)
            .unwrap_or_default();
        let peer_reset_support = peer
            .map(<StreamResetsOfParts<L> as PeerResetSupportFrom<TransportParameterSlots<L>, Jr>>::peer_reset_support)
            .unwrap_or_default();
        let config = parents
            .get::<StreamSetConfig<StreamSetConfigOf<T>>, Ic>()
            .0
            .clone();
        let events = parents
            .get::<ConnectionEventSink<EventsOf<T, L>>, Iev>()
            .events()
            .shared();
        let intake = {
            let mut core = parents.get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Isc>();
            match core.strategy_mut() {
                Some(strategy) => <StreamSetFamilyOf<T> as ComponentIntake<
                    SendTypes<T, L>,
                    StreamIntent<SendParametersOf<T>>,
                    Ij,
                >>::intake(strategy),
                // every link path drained, so nothing the set publishes is
                // sent: a core of its own gives what it asks for
                None => <StreamSetFamilyOf<T> as ComponentIntake<
                    SendTypes<T, L>,
                    StreamIntent<SendParametersOf<T>>,
                    Ij,
                >>::intake(&mut SendStrategyOf::<T, L>::default()),
            }
        };
        let set = X::new(
            StreamSetFacts {
                role: <T::Side as Side>::ROLE,
                granted_to_peer,
                granted_by_peer,
                peer_reset_support,
            },
            config,
            events,
            intake,
        );
        parents
            .get_mut::<ConnectionHandleStateOf<T, L>, Ih>()
            .layer_built();
        set
    }

    fn end<'v, B: CallBundle>(
        mut self,
        parents: &mut ParentsOf<'v, T, L, layer::Established>,
        others: &mut OtherNodes<'v, T, L, B>,
    ) {
        let Some(end) = layer_end::<T, L, B, Ir>(parents, others) else {
            // invariant: read in the layer's end action, the end is known
            debug_assert!(false, "the established layer ends without a reason");
            return;
        };
        let changed = {
            let mut publisher = parents.get_mut::<SendStrategyPublisher<PublisherOf<T, L>>, In>();
            self.layer_ended::<Ij, _>(publisher.publisher_mut(), end.clone());
            publisher.take_changed()
        };
        if let Some(changed) = changed {
            parents.publish(changed);
        }
        parents
            .get_mut::<ConnectionHandleStateOf<T, L>, Ih>()
            .layer_ended(end);
    }
}

/// How the established layer ends, as its end actions read it: rejected,
/// when the request to end it says so (RFC 9001 §4.6.2), and otherwise for
/// the reason in the record of why the connection closed.
///
/// A rejected layer is built anew only while the record is empty, so the
/// two cannot both hold. `None` while the layer has not ended: the record
/// is empty and the layer was not rejected. No end of the layer leaves it
/// so, as whatever ends it otherwise writes the record first, and a dropped
/// future writes it before any node ends; read in an end action, it is
/// `Some`.
pub fn layer_end<'v, T, L, B, Ir>(
    parents: &mut ParentsOf<'v, T, L, layer::Established>,
    others: &OtherNodes<'v, T, L, B>,
) -> Option<LayerEnd<CloseCauseOf<T, L>>>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    B: CallBundle,
    for<'x> <L as LineageLists<'x, T>>::Connection:
        GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>,
{
    if others.established_end() == Some(EstablishedEnd::ZeroRttRejected) {
        return Some(LayerEnd::ZeroRttRejected);
    }
    parents
        .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
        .reason()
        .cloned()
        .map(LayerEnd::ConnectionClosed)
}

/// What the stream set takes from its layer's lineage to hear of the
/// peer's transport parameters: itself, and the send strategy's publisher
/// it is lent.
type SetAndPublisher<X, T, L> = frunk_core::HList![X, SendStrategyPublisher<PublisherOf<T, L>>];

/// The stream set has no deadline: the dispatch of frames and the
/// application change it. It subscribes to the peer's transport parameters
/// becoming known: once they are, it takes the limits they grant and what
/// they allow the resets ([`StreamSet::peer_transport_parameters_known`]), lent the send
/// strategy's publisher, and what changed there is handed on at the
/// connection. A layer built on the known parameters gets the same limits
/// again; a client's early layer, built on the remembered ones, gets the
/// server's of this handshake (RFC 9000 §7.4.1).
///
/// When the driver panicked, it is told the layer's end
/// ([`StreamSet::driver_panicked`]), for the reason in the record of why
/// the connection closed, which the dropped future wrote.
///
/// `Ip` is where the peer's transport parameters are in the lineage, `Jp`
/// and `Jr` where the flow control parameters and those that allow the
/// resets are among their slots, `In` where the publisher is, and `Ij` the
/// place of the stream intents in the sum of intents.
impl<T, L, X, Is, Ir, Ip, Jp, Jr, In, Ij>
    DataComponent<T, L, layer::Established, (ChosenStreamSet, Is, Ir, (Ip, Jp, Jr, In, Ij))> for X
where
    T: Choices<
        Host: HostChoices<
            T,
            Streams: StreamSetFamily<
                Set<
                    CloseCauseOf<T, L>,
                    SendTypes<T, L>,
                    StreamResetsOfParts<L>,
                    SharedEventsOf<T, L>,
                > = X,
            >,
        >,
    >,
    L: LineagePartList<T>
        + ConnectionErrorsOf
        + StreamResetsOf
        + ParametersOf<TransportParameterSpace>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    X: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            SendParameters = SendParametersOf<T>,
        > + 'static,
    PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, Ij>,
    TransportParameterSlots<L>: FlowControlParameterSlots<Jp>,
    StreamResetsOfParts<L>: PeerResetSupportFrom<TransportParameterSlots<L>, Jr>,
    for<'v> <L as LineageLists<'v, T>>::Established: GetAt<X, Is>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>
        + TakeEach<'v, SetAndPublisher<X, T, L>, frunk_core::HList![Is, In]>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<PeerTransportParametersKnown>();
    }

    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        lineage: LineageOf<'v, T, L, layer::Established>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let (granted, reset_support) = lineage
            .get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>()
            .known()
            .map(|known| {
                (
                    FlowControlParameterSlots::<Jp>::flow_control_parameters(known),
                    <StreamResetsOfParts<L> as PeerResetSupportFrom<TransportParameterSlots<L>, Jr>>::peer_reset_support(known),
                )
            })?;
        let (frunk_core::hlist_pat![mut set, mut publisher], mut rest) =
            Take::<SetAndPublisher<X, T, L>, frunk_core::HList![Is, In]>::take(lineage);
        set.peer_transport_parameters_known::<Ij, _>(
            publisher.publisher_mut(),
            granted,
            reset_support,
        );
        if let Some(changed) = publisher.take_changed() {
            rest.publish(changed);
        }
        None
    }

    fn future_dropped<'v>(
        lineage: &mut LineageOf<'v, T, L, layer::Established>,
        cause: AbortCause,
    ) {
        if cause != AbortCause::Panicked {
            return;
        }
        let reason = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
            .reason()
            .cloned()
            .unwrap_or(CloseReason::Aborted(AbortCause::Panicked));
        lineage
            .get_mut::<X, Is>()
            .driver_panicked(LayerEnd::ConnectionClosed(reason));
    }
}
