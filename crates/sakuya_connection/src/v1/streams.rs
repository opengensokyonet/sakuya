//! The streams of a connection in its established layer: the trait of the
//! stream set ([`StreamSet`]), the facts it is made from, the failures of
//! the frames it takes, and how version 1 builds and ends it.
//!
//! The established layer of version 1 holds one stream set, of the type the
//! composition chooses ([`Choices::Streams`]). It is made when the layer is
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
//! [`LockedStreamSet`](locked::LockedStreamSet).
//!
//! The set also writes the nine frames, through one kind of frame source
//! for each, and keeps the tickets of their intents, which it publishes
//! through the send strategy's intake ([`send`]).

pub mod locked;
pub mod send;

use bytes::Bytes;
use sakuya_stream::{
    connection::LayerEnd,
    receive::violation::{OnResetStreamError, OnStreamFrameError},
    send_options::destination::Unfulfilled,
    stream_id_ledger::{ReceivingPartFrameError, SendingPartFrameError},
};
use sakuya_wire::{
    parameters::ParametersOf,
    parts::Selector,
    v1::{
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

use self::send::{
    DataBlockedSummary, MaxDataSummary, MaxStreamDataSummary, MaxStreamsSummary,
    ResetStreamSummary, StopSendingSummary, StreamDataBlockedSummary, StreamIntent,
    StreamIntentHandle, StreamIntentKey, StreamIntentTicketOf, StreamSetFrameSummary,
    StreamSummary, StreamsBlockedSummary,
};
use super::{
    Choices, CloseCauseOf, ConnectionArgs, Side,
    close::CloseReasonRecord,
    own_args,
    parameters::{LocalTransportParameters, PeerTransportParameters},
    send::SendTypes,
    send_planning::IntakePublishOutcome,
};
use crate::{
    call::CallBundle,
    component::{ArgsOf, Build, DataComponent, ParentsOf, PassiveDataComponent},
    error::ConnectionErrorsOf,
    layer,
    others::OtherNodes,
    send_strategy::{AnyActiveLinkPath, IntentTicketResize, IntentTicketWithdraw},
    share::{ConnectionArgsOf, LineageLists, LineagePartList},
    take::GetAt,
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// The set of a connection's streams in its established layer.
///
/// `Lc` is the type of this endpoint's reason for closing the connection,
/// which the errors of the streams carry, and `K` the ticket the send
/// strategy's intake gives back for a stream intent, which the set keeps.
/// The driver hands it the frames of streams and flow control, one method
/// for each of the nine frames, and the end of the layer; the application
/// opens and accepts streams through its [`Handle`](Self::Handle).
///
/// A frame that names a stream passes the checks of the streams' identity
/// before it reaches the part of the stream it concerns. A frame that fails
/// returns a [`StreamSetFrameError`], and the connection closes: the frames
/// after it in the packet are not handed over, and what the failed frame
/// changed is not undone.
///
/// The set also writes the nine frames: each of its frame sources
/// ([`send`]) gives it the item planned, with the handle the set publishes
/// its intents through, and takes back the summaries of the frames written
/// once their packets are delivered or lost. Every method that may change
/// what is to be sent is given the handle, `publish`, and leaves the
/// intents matching what is due afterwards.
pub trait StreamSet<Lc, K>: Sized {
    /// What the application opens and accepts streams through; the
    /// established layer's handle keeps one.
    type Handle: Clone;

    /// What the composition configures the stream set with; the connection
    /// node keeps it from the connection's making until the established
    /// layer is built. Its default is what a composition that sets nothing
    /// gets.
    type Config: Clone + Default;

    /// The parameters application data is sent with: what the stream
    /// intents of the data carry.
    type SendParameters;

    /// The stream set of an established layer, from the facts of the
    /// connection and the configuration.
    fn new(facts: StreamSetFacts, config: Self::Config) -> Self;

    /// A handle for the application.
    fn handle(&self) -> Self::Handle;

    /// Takes a STREAM frame, which arrived in a packet protected at `level`.
    ///
    /// # Errors
    ///
    /// [`StreamSetFrameError`] if the frame breaks a rule of streams or flow
    /// control; the connection closes.
    fn on_stream_frame<P>(
        &mut self,
        publish: &P,
        level: EncryptionLevel,
        frame: StreamFrame<Bytes>,
    ) -> Result<(), StreamSetFrameError>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// Takes a RESET_STREAM frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_reset_stream<P>(
        &mut self,
        publish: &P,
        frame: ResetStreamFrame,
    ) -> Result<(), StreamSetFrameError>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// Takes a STOP_SENDING frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_stop_sending<P>(
        &mut self,
        publish: &P,
        frame: StopSendingFrame,
    ) -> Result<(), StreamSetFrameError>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// Takes a MAX_DATA frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_max_data<P>(
        &mut self,
        publish: &P,
        frame: MaxDataFrame,
    ) -> Result<(), StreamSetFrameError>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// Takes a MAX_STREAM_DATA frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_max_stream_data<P>(
        &mut self,
        publish: &P,
        frame: MaxStreamDataFrame,
    ) -> Result<(), StreamSetFrameError>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// Takes a MAX_STREAMS frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_max_streams<P>(
        &mut self,
        publish: &P,
        frame: MaxStreamsFrame,
    ) -> Result<(), StreamSetFrameError>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// Takes a DATA_BLOCKED frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_data_blocked<P>(
        &mut self,
        publish: &P,
        frame: DataBlockedFrame,
    ) -> Result<(), StreamSetFrameError>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// Takes a STREAM_DATA_BLOCKED frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_stream_data_blocked<P>(
        &mut self,
        publish: &P,
        frame: StreamDataBlockedFrame,
    ) -> Result<(), StreamSetFrameError>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// Takes a STREAMS_BLOCKED frame.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    fn on_streams_blocked<P>(
        &mut self,
        publish: &P,
        frame: StreamsBlockedFrame,
    ) -> Result<(), StreamSetFrameError>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// The established layer ended as `end`: every stream hears of it, and
    /// every later operation on the set reports it.
    fn layer_ended(&mut self, end: LayerEnd<Lc>);

    /// Writes STREAM frames of the stream `stream_id`: its data, its FIN,
    /// and first exposes what they use before it returns.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_stream<P, W, Q>(
        &mut self,
        publish: &P,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: From<StreamSummary>,
        Q: PacketPosition;

    /// Writes the RESET_STREAM frame of the stream `stream_id`, as its
    /// end is now, and first exposes its final size before it returns.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_reset_stream<P, W, Q>(
        &mut self,
        publish: &P,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: From<ResetStreamSummary>,
        Q: PacketPosition;

    /// Writes the STOP_SENDING frame of the stream `stream_id`.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_stop_sending<P, W, Q>(
        &mut self,
        publish: &P,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: From<StopSendingSummary>,
        Q: PacketPosition;

    /// Writes the MAX_DATA frame of the connection's limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_max_data<P, W, Q>(
        &mut self,
        publish: &P,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: From<MaxDataSummary>,
        Q: PacketPosition;

    /// Writes the MAX_STREAM_DATA frame of the stream `stream_id`'s limit
    /// now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_max_stream_data<P, W, Q>(
        &mut self,
        publish: &P,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: From<MaxStreamDataSummary>,
        Q: PacketPosition;

    /// Writes the MAX_STREAMS frame of the peer's streams of
    /// `directionality`, with their limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_max_streams<P, W, Q>(
        &mut self,
        publish: &P,
        directionality: Directionality,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: From<MaxStreamsSummary>,
        Q: PacketPosition;

    /// Writes the DATA_BLOCKED frame of the connection's limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_data_blocked<P, W, Q>(
        &mut self,
        publish: &P,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: From<DataBlockedSummary>,
        Q: PacketPosition;

    /// Writes the STREAM_DATA_BLOCKED frame of the stream `stream_id`'s
    /// limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_stream_data_blocked<P, W, Q>(
        &mut self,
        publish: &P,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: From<StreamDataBlockedSummary>,
        Q: PacketPosition;

    /// Writes the STREAMS_BLOCKED frame of this side's streams of
    /// `directionality`, with their limit now.
    ///
    /// It writes nothing, having resized or withdrawn the intent, when
    /// nothing is due or the frame does not fit.
    fn supply_streams_blocked<P, W, Q>(
        &mut self,
        publish: &P,
        directionality: Directionality,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
        W: PacketWriting,
        SummaryOf<W>: From<StreamsBlockedSummary>,
        Q: PacketPosition;

    /// The packet a frame of `summary` was written into was acknowledged.
    fn on_frame_delivered<P>(&mut self, publish: &P, summary: StreamSetFrameSummary)
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// The packet a frame of `summary` was written into was declared lost,
    /// or its send result is unknown, or its link path ended before it was
    /// settled. A later acknowledgment of it may still come.
    fn on_frame_lost<P>(&mut self, publish: &P, summary: StreamSetFrameSummary)
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;

    /// The intent of `key` was not fulfilled for `cause`.
    fn on_intent_unfulfilled<P>(&mut self, publish: &P, key: StreamIntentKey, cause: Unfulfilled)
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;
}

/// What a stream set is made from that the connection knows: this side's
/// role and the flow control transport parameters of both sides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamSetFacts {
    /// The role of this side.
    pub role: Role,
    /// This side's transport parameters: the limits it grants the peer,
    /// which set how much the streams receive.
    pub granted_to_peer: FlowControlParameters,
    /// The peer's transport parameters: the limits the peer grants this
    /// side, which set how much the streams send.
    pub granted_by_peer: FlowControlParameters,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum StreamSetFrameError {
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
    /// The receiving part of the stream rejected a RESET_STREAM frame: it
    /// breaks a rule of final sizes or of flow control (RFC 9000 §4.1,
    /// §4.5).
    #[snafu(display("RESET_STREAM frame rejected"))]
    ResetStream {
        /// The broken rule.
        source: OnResetStreamError,
    },
}

impl StreamSetFrameError {
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

/// The stream set of the choices `T` and the list of parts `L`, which keeps
/// the tickets the strategy's intake gives back for the stream intents.
pub type StreamsOf<T, L> = <T as Choices>::Streams<CloseCauseOf<T, L>, StreamIntentTicketOf<T, L>>;

/// The configuration of the stream set, `C`, kept in the connection node
/// until the established layer is built.
#[derive(Debug)]
pub struct StreamSetConfig<C>(pub C);

/// The connection keeps the configuration it was made with.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for StreamSetConfig<T::StreamSetConfig>
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
/// It has no deadline and reads nothing; the stream set is made from it.
impl<C> PassiveDataComponent for StreamSetConfig<C> {}

/// Where the stream set is among the established layer's components.
#[derive(Debug)]
pub struct ChosenStreamSet;

/// The stream set is made when the established layer is built: from this
/// side's role, this side's transport parameters as sent and the peer's as
/// received, and the configuration the connection node keeps.
///
/// Version 1 asks for the layer once both are there
/// ([`EstablishedLayerReady`](super::advancing::EstablishedLayerReady)). A
/// layer another part asks for before takes this side's parameters as
/// configured, and the peer's as absent: no stream and no data.
///
/// When the layer ends, every stream hears that the connection closed, for
/// the reason in the record of why the connection closed.
impl<T, L, X, Il, Ip, Ic, Ir, Jl, Jp>
    Build<T, L, layer::Established, (ChosenStreamSet, (Il, Ip, Ic, Ir), (Jl, Jp))> for X
where
    T: Choices<Streams<CloseCauseOf<T, L>, StreamIntentTicketOf<T, L>> = X>,
    L: LineagePartList<T> + ConnectionErrorsOf + ParametersOf<TransportParameterSpace>,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    X: StreamSet<CloseCauseOf<T, L>, StreamIntentTicketOf<T, L>, Config = T::StreamSetConfig>,
    TransportParameterSlots: FlowControlParameterSlots<Jl>,
    TransportParameterSlots<L>: FlowControlParameterSlots<Jp>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<LocalTransportParameters<TransportParameterSlots>, Il>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>
        + GetAt<StreamSetConfig<T::StreamSetConfig>, Ic>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::Established>,
        _: &mut ArgsOf<T, L, layer::Established>,
    ) -> Self {
        let granted_to_peer =
            match parents.get::<LocalTransportParameters<TransportParameterSlots>, Il>() {
                LocalTransportParameters::Sent(sent) => sent,
                LocalTransportParameters::Configured(configured) => configured,
            }
            .flow_control_parameters();
        let granted_by_peer = parents
            .get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>()
            .known()
            .map(FlowControlParameterSlots::flow_control_parameters)
            .unwrap_or_default();
        let config = parents
            .get::<StreamSetConfig<T::StreamSetConfig>, Ic>()
            .0
            .clone();
        X::new(
            StreamSetFacts {
                role: <T::Side as Side>::ROLE,
                granted_to_peer,
                granted_by_peer,
            },
            config,
        )
    }

    fn end<'v, B: CallBundle>(
        mut self,
        parents: &mut ParentsOf<'v, T, L, layer::Established>,
        _: &mut OtherNodes<'v, T, L, B>,
    ) {
        let reason = parents
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
            .reason()
            .cloned();
        match reason {
            Some(reason) => self.layer_ended(LayerEnd::ConnectionClosed(reason)),
            // invariant: only a written record ends the established layer,
            // asking for it or for the connection's end, and a dropped
            // future writes it before any node ends; without 0-RTT no
            // other end of the layer exists
            None => debug_assert!(false, "the established layer ends without a reason"),
        }
    }
}

/// The stream set has no deadline and reads nothing: the dispatch of frames
/// and the application change it.
impl<T, L, X> DataComponent<T, L, layer::Established, ChosenStreamSet> for X
where
    T: Choices<Streams<CloseCauseOf<T, L>, StreamIntentTicketOf<T, L>> = X>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
{
}
