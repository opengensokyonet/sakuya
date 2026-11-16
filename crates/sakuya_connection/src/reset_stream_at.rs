//! The reliable stream reset extension (RESET_STREAM_AT) as a part of a
//! connection, as specified by the Internet-Draft
//! [draft-ietf-quic-reliable-stream-reset-11]; the draft is not an RFC and
//! may still change.
//!
//! With the part a composition resets its streams reliably
//! ([`ReliableStreamResets`]): a stream writer may reset at a reliable
//! size ([`StreamResetAt`]), which RESET_STREAM_AT announces, and a stream
//! reader keeps the reliable size of the peer's. The part has no intents
//! and no frame sources of its own: the reset frames of version 1's streams
//! are those of the reset kind, RESET_STREAM_AT among them.
//!
//! - **Transport parameter.** The part sends `reset_stream_at` (§3) as it is
//!   configured: its share of the connection node is its own
//!   [`LocalTransportParameters`], made from the slots the part is given
//!   when the connection is made (its `Args`, [`Part`]). A composition with
//!   the part need not announce it. A value of the peer's that is not
//!   empty closes the connection with TRANSPORT_PARAMETER_ERROR (§3).
//! - **Sending.** A stream writer resets at a reliable size only when the
//!   peer announced the parameter: the stream set takes what the peer
//!   allows from the peer's parameters when it is made
//!   ([`PeerResetSupportSlots`]), and otherwise the reset fails with
//!   [`ResetAtError::NotSupportedByPeer`]; no RESET_STREAM_AT is sent then.
//! - **Receiving.** A RESET_STREAM_AT that arrives when this side did not
//!   announce the parameter closes the connection with
//!   FRAME_ENCODING_ERROR before the stream it names is looked for: for
//!   this connection it is a frame of a type it does not know (RFC 9000
//!   §12.4). Otherwise the stream set takes it ([`ResetStreamAtSet`]). A
//!   reset that changes the error code of an earlier one of the stream,
//!   RESET_STREAM as well as RESET_STREAM_AT, closes the connection with
//!   STREAM_STATE_ERROR (§5.2).
//!
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html

use core::convert::Infallible;

use bytes::{Buf, Bytes, BytesMut};
use frunk_core::hlist_pat;
use nitori_call::{Direct, Receiver};
use nitori_io::{Read, ReadChunk};
use sakuya_stream::{
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::ConnectionSendFlowController,
    receive::{
        StreamReceiver, flow_control::ReceiveFlowControlPolicy,
        termination::ReceiveTerminationPolicy,
    },
    receive_buffer::StreamReceiveBuffer,
    reset_stream_at::{
        receive::{OnResetStreamError, RemoteResetAt},
        send::{self, LocalResetAt, LocalResetAtFrame, PeerResetStreamAtSupport},
    },
    send::{
        StreamSender, finish::ResetError, flow_control::SendFlowControlPolicy,
        termination::ResetOnAbandonTermination, termination::SendTerminationPolicy,
    },
    send_buffer::{SendMarker, StreamSendBuffer},
};
use sakuya_wire::{
    parameters::{ParametersPart, TrailingBytesError},
    parts::{Coprod, Coproduct, HList, HNil, PartsError, Selector},
    reset_stream_at::{
        FrameType, ResetStreamAt, ResetStreamAtFrame,
        codec::{self, ReadResetStreamAtFrameError, WriteResetStreamAtFrameHostExt as _},
    },
    v1::{
        application_error::ApplicationErrorCode,
        frame::{
            reset_stream::{ResetStreamFrame, codec::WriteResetStreamFrameHostExt as _},
            set::{FrameFieldsError, FrameSetPart, FrameTypeValues},
        },
        transport_error::TransportErrorCode,
        transport_parameters::TransportParameterSpace,
    },
    var_int::VarInt,
};
use snafu::{ResultExt, Snafu, ensure};

use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{ArgsOf, Build, LineageOf, ParentsOf},
    dispatch::{DispatchFacts, FrameDispatch},
    error::{ConnectionErrorPart, ConnectionErrorsOf, TransportParameterValueErrorPart},
    frame_source::{FrameSourcePart, PacketKind},
    layer::{self, LogicalPath},
    others::OtherNodes,
    send_strategy::{
        AnyActiveLinkPath, IntentTicketResize, IntentTicketWithdraw, SendIntentIntake,
        SendIntentPart, SendStrategy, SendStrategyTypes, SharedPublishTo,
    },
    share::{
        ConnectionArgsOf, FlatMut, LayerShare, LineageLists, LineagePartList, LinkPathIdentifierOf,
        LogicalPathKeyShare, NodeData,
    },
    take::{GetAt, TakeEach},
    v1::{
        Choices, CloseCauseOf,
        application_handles::stream::{StreamWrite, StreamWriter},
        close::{CloseReasonRecord, TransportClose},
        parameters::{LocalTransportParameters, PartSlots},
        send::SendTypes,
        send_planning::{IntakeOf, IntakePublishOutcome, SendStrategyIntake, SendStrategyOf},
        streams::{
            StreamSet, StreamSetFrameError, StreamSetFrameErrorOf, StreamsOf,
            resets::{
                OnResetStreamErrorOf, PeerResetSupportSlots, ResetStreamViolation, StreamResets,
                StreamResetsOf, StreamResetsOfParts, StreamResetsPart,
            },
            send::{StreamIntent, StreamIntentHandle, StreamIntentHandleOf, StreamIntentTicketOf},
        },
    },
    write::{DelimitedFrame, InFlightClass},
};

/// The reliable stream reset extension, one part of a composition.
///
/// What the part is given when the connection is made, its `Args`, is the
/// slots of its transport parameter, as it sends them: `hlist![Some(ResetStreamAt)]`
/// announces `reset_stream_at`, which is what a composition with the part
/// is for, and `hlist![None]` leaves it out.
#[derive(Debug)]
pub struct Part;

// ---- the reset kind ----

/// The resets of the extension: a stream sends RESET_STREAM_AT as well as
/// RESET_STREAM ([`LocalResetAt`]) and keeps the reliable size of the
/// peer's ([`RemoteResetAt`]); a reset that changes the error code of an
/// earlier one is a STREAM_STATE_ERROR (§5.2).
///
/// A sending part resets at a reliable size only when the peer announced
/// `reset_stream_at`: [`PeerSupport`](StreamResets::PeerSupport) is the
/// peer's [`PeerResetStreamAtSupport`], if it gave one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReliableStreamResets;

impl StreamResets for ReliableStreamResets {
    type Local = LocalResetAt;
    type Remote = RemoteResetAt;
    type OnResetStreamError = OnResetStreamError;
    type SendTermination = ResetOnAbandonTermination;
    type PeerSupport = Option<PeerResetStreamAtSupport>;

    fn send_termination(
        abandon_code: ApplicationErrorCode,
        destination_exhausted_code: ApplicationErrorCode,
    ) -> ResetOnAbandonTermination {
        ResetOnAbandonTermination::new(abandon_code, destination_exhausted_code)
    }

    fn on_reset_stream<C, Lc>(
        receiver: &mut StreamReceiver<C, Lc, RemoteResetAt>,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError>
    where
        C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<RemoteResetAt>,
    {
        receiver.on_reset_stream(frame, connection)
    }

    fn reset<C, K, Lc, B, M>(
        sender: &mut StreamSender<C, K, Lc, LocalResetAt, B, M>,
        error_code: ApplicationErrorCode,
    ) -> Result<(), ResetError<Lc>>
    where
        K: ConnectionSendFlowController,
        M: SendMarker,
        C: StreamSendBuffer<B, K::Reservation, M>
            + SendFlowControlPolicy<LocalResetAt>
            + SendTerminationPolicy<LocalResetAt>,
    {
        sender.reset(error_code)
    }
}

/// The rules of RESET_STREAM and RESET_STREAM_AT on a stream that takes
/// both.
impl ResetStreamViolation for OnResetStreamError {
    fn transport_error_code(&self) -> TransportErrorCode {
        OnResetStreamError::transport_error_code(self)
    }
}

/// The peer allows RESET_STREAM_AT when its parameters hold
/// `reset_stream_at`.
impl<S, I> PeerResetSupportSlots<ReliableStreamResets, I> for S
where
    S: Selector<Option<ResetStreamAt>, I>,
{
    fn peer_reset_support(&self) -> Option<PeerResetStreamAtSupport> {
        Selector::<Option<ResetStreamAt>, I>::get(self)
            .map(PeerResetStreamAtSupport::from_peer_parameter)
    }
}

/// The streams of the composition reset reliably.
impl StreamResetsPart for Part {
    type Fold<Prev: StreamResets> = ReliableStreamResets;
}

// ---- the frames written ----

/// The invariant of every write here: a `BytesMut` takes every byte, so
/// writing into one does not fail.
const TAKES_EVERY_BYTE: &str = "a BytesMut takes every byte";

/// RESET_STREAM_AT counts in flight and elicits an acknowledgment, as
/// RESET_STREAM does.
impl DelimitedFrame for ResetStreamAtFrame {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        ResetStreamAtFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        buffer
            .sync_write_reset_stream_at_frame_unpin(self)
            .expect(TAKES_EVERY_BYTE);
    }
}

/// The reset frame of a [`LocalResetAt`] is written as the frame it is.
impl DelimitedFrame for LocalResetAtFrame {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        match self {
            Self::ResetStream(frame) => DelimitedFrame::encoded_len(frame),
            Self::ResetStreamAt(frame) => DelimitedFrame::encoded_len(frame),
        }
    }

    fn write_to(self, buffer: &mut BytesMut) {
        match self {
            Self::ResetStream(frame) => buffer
                .sync_write_reset_stream_frame_unpin(frame)
                .expect(TAKES_EVERY_BYTE),
            Self::ResetStreamAt(frame) => DelimitedFrame::write_to(frame, buffer),
        }
    }
}

// ---- the stream set ----

/// A stream set that takes RESET_STREAM_AT frames (`ResetStreamAtSet`), of
/// the reset kind `X`.
pub trait ResetStreamAtSet<Lc, K, X: StreamResets>: StreamSet<Lc, K, X> {
    /// Takes a RESET_STREAM_AT frame, which this side announced it receives.
    ///
    /// # Errors
    ///
    /// As [`StreamSet::on_reset_stream`]: the frame names a stream it must
    /// not, or the stream's receiving part rejects it; the connection
    /// closes.
    fn on_reset_stream_at<P>(
        &mut self,
        publish: &P,
        frame: ResetStreamAtFrame,
    ) -> Result<(), StreamSetFrameErrorOf<X>>
    where
        P: StreamIntentHandle<Self::SendParameters, K>,
        K: IntentTicketResize + IntentTicketWithdraw;
}

// ---- the stream writer ----

/// What a stream's sending part can be asked besides [`StreamWrite`] in a
/// composition with the extension (`StreamResetAt`): to reset at a reliable
/// size.
///
/// The semantics are those of the sending part
/// (`sakuya_stream::reset_stream_at::send`).
pub trait StreamResetAt: StreamWrite {
    /// Resets the stream with `code`, keeping the reliable delivery of its
    /// first `reliable_size` bytes, and ends it with RESET_STREAM_AT, also
    /// for a reliable size of zero.
    ///
    /// # Errors
    ///
    /// [`ResetAtError::NotSupportedByPeer`] first, then the sending part's
    /// [`send::ResetAtError`]; nothing changes then.
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<Self::CloseCause>>;
}

/// [`StreamResetAt::reset_at`] fails; `C` is this endpoint's reason for
/// closing.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ResetAtError<C> {
    /// The peer did not announce `reset_stream_at`, so no RESET_STREAM_AT
    /// may be sent to it (§3).
    #[snafu(display("the peer does not take RESET_STREAM_AT"))]
    NotSupportedByPeer,
    /// The sending part refused the reset.
    #[snafu(transparent)]
    Stream {
        /// The sending part's failure.
        source: send::ResetAtError<C>,
    },
}

/// A borrowed share resets as the share does.
impl<E: StreamResetAt + ?Sized> StreamResetAt for &mut E {
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<E::CloseCause>> {
        (**self).reset_at(code, reliable_size)
    }
}

/// The writer resets through its share.
impl<E: StreamResetAt, O> StreamResetAt for StreamWriter<E, O> {
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<E::CloseCause>> {
        self.share.reset_at(code, reliable_size)
    }
}

// ---- the error ----

/// An error of the extension in a connection: one variant for each kind of
/// failure, each with the transport error code it closes with.
///
/// `R` is the failure of a reset frame of the reset kind of the
/// composition, by default the extension's ([`OnResetStreamErrorOf`]).
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ConnectionError<R = OnResetStreamError> {
    /// A RESET_STREAM_AT frame arrived, though this side did not announce
    /// `reset_stream_at`: for this connection the frame is of a type it does
    /// not know (FRAME_ENCODING_ERROR, RFC 9000 §12.4).
    #[snafu(display("RESET_STREAM_AT frame without reset_stream_at announced"))]
    NotAnnounced,
    /// The fields of a RESET_STREAM_AT frame could not be read.
    #[snafu(display("RESET_STREAM_AT frame fields read failed"))]
    ReadFrameFields {
        /// The failure.
        source: ReadResetStreamAtFrameError<Infallible>,
    },
    /// The stream set rejected a RESET_STREAM_AT frame: it names a stream it
    /// must not, or the stream's receiving part rejected it.
    #[snafu(display("RESET_STREAM_AT frame rejected by the streams"))]
    StreamSet {
        /// The broken rule.
        source: StreamSetFrameError<R>,
    },
    /// A RESET_STREAM_AT frame arrived while the connection has no
    /// established layer and is not closing; the connection closes with
    /// INTERNAL_ERROR. It does not happen, as for version 1's frames of
    /// streams.
    #[snafu(display("RESET_STREAM_AT frame without an established layer"))]
    NoEstablishedLayer,
    /// The peer's `reset_stream_at` has a value that is not empty
    /// (TRANSPORT_PARAMETER_ERROR, §3).
    #[snafu(display("reset_stream_at value rejected"))]
    ParameterValue {
        /// The broken rule.
        source: TrailingBytesError,
    },
}

/// The Frame Type value of RESET_STREAM_AT (§4).
const RESET_STREAM_AT_FRAME_TYPE: u32 = 0x24;

/// The Frame Type field holds RESET_STREAM_AT for a failure of a frame; the
/// reason phrase is what this layer shows, without its sources.
impl<R: ResetStreamViolation> TransportClose for ConnectionError<R> {
    fn code(&self) -> TransportErrorCode {
        match self {
            Self::NotAnnounced => TransportErrorCode::FRAME_ENCODING_ERROR,
            Self::ReadFrameFields { source } => source.transport_error_code(),
            Self::StreamSet { source } => source.transport_error_code(),
            Self::NoEstablishedLayer => TransportErrorCode::INTERNAL_ERROR,
            Self::ParameterValue { .. } => TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        }
    }

    fn frame_type(&self) -> Option<VarInt> {
        match self {
            Self::NotAnnounced
            | Self::ReadFrameFields { .. }
            | Self::StreamSet { .. }
            | Self::NoEstablishedLayer => Some(VarInt::from_u32(RESET_STREAM_AT_FRAME_TYPE)),
            Self::ParameterValue { .. } => None,
        }
    }

    fn reason_phrase(&self) -> Bytes {
        Bytes::from(self.to_string())
    }
}

/// The error of the extension in a connection of the list of parts `L`,
/// whose failures of reset frames are those of how `L` resets streams.
pub type ResetStreamAtConnectionErrorOf<L> = ConnectionError<OnResetStreamErrorOf<L>>;

impl<L: StreamResetsOf> ConnectionErrorPart<L> for Part {
    type ConnectionError = ResetStreamAtConnectionErrorOf<L>;
}

/// The one parameter of the extension takes no value.
impl<L: StreamResetsOf> TransportParameterValueErrorPart<Coprod![TrailingBytesError], L> for Part {
    fn value_error(
        id: VarInt,
        source: PartsError<Coprod![TrailingBytesError]>,
    ) -> ResetStreamAtConnectionErrorOf<L> {
        debug_assert_eq!(
            id,
            <ResetStreamAt as sakuya_wire::parameters::KeyedParameter>::ID,
            "the extension has one parameter"
        );
        let PartsError(Coproduct::Inl(source)) = source;
        ConnectionError::ParameterValue { source }
    }
}

// ---- the part's shares ----

/// The extension adds nothing to the key of a logical path.
impl LogicalPathKeyShare for Part {
    type Fields = HNil;
}

/// The transport parameters of the extension are those its wire format
/// defines.
impl ParametersPart<TransportParameterSpace> for Part {
    type Parameters =
        <sakuya_wire::reset_stream_at::Part as ParametersPart<TransportParameterSpace>>::Parameters;
}

/// The extension has no intents and no frame sources: version 1's streams
/// write its reset frames.
impl SendIntentPart for Part {
    type FrameSourceId = sakuya_wire::parts::CNil;
    type SendIntents = sakuya_wire::parts::CNil;
    type FrameSources = HNil;
}

impl<K: PacketKind> FrameSourcePart<K> for Part {
    fn item(intent: &sakuya_wire::parts::CNil) -> Option<sakuya_wire::parts::CNil> {
        match *intent {}
    }
    fn source(item: &sakuya_wire::parts::CNil) -> sakuya_wire::parts::CNil {
        match *item {}
    }
}

/// The connection node keeps the extension's transport parameters as this
/// side sends them, made from the part's `Args`.
impl<T: Choices, L> LayerShare<T, L, layer::Connection> for Part {
    type Data = HList![LocalTransportParameters<PartSlots<Part>>];
    type Calls = HNil;
    type Args = PartSlots<Part>;
}

macro_rules! no_share {
    ($($lv:ident),*) => {$(
        /// The extension keeps nothing in this layer.
        impl<T: Choices, L> LayerShare<T, L, layer::$lv> for Part {
            type Data = HNil;
            type Calls = HNil;
        }
    )*};
}
no_share!(LinkEntry, LogicalPath, LinkPath, Established, Recovery);

/// The extension's transport parameters start as configured; the part
/// marks where they are among the components, apart from version 1's.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (Part, I)>
    for LocalTransportParameters<PartSlots<Part>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<PartSlots<Part>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        LocalTransportParameters::Configured(*Selector::<PartSlots<Part>, I>::get(args))
    }
}

// ---- the frames received ----

/// The extension reads its frames as the wire format's part.
impl FrameSetPart for Part {
    type Run<D> = ResetStreamAtFrame;
    type Kind = FrameType;
    type TypeValue = FrameType;
    type FieldsError<E> = codec::ReadResetStreamAtFrameError<E>;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::FRAME_TYPE_VALUES;

    fn type_value_of(value: VarInt) -> Option<FrameType> {
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::type_value_of(value)
    }

    fn kind_of(type_value: FrameType) -> FrameType {
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::kind_of(type_value)
    }

    fn run_kind<D>(run: &ResetStreamAtFrame) -> FrameType {
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::run_kind::<D>(run)
    }

    fn read_run<H>(
        source: &mut H,
        type_value: FrameType,
    ) -> Result<
        <Self as FrameSetPart>::Run<<Direct<H> as ReadChunk>::Chunk>,
        <Self as FrameSetPart>::FieldsError<<Direct<H> as Read>::Error>,
    >
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>,
    {
        <sakuya_wire::reset_stream_at::Part as FrameSetPart>::read_run(source, type_value)
    }
}

/// Check that this side announced `reset_stream_at` in the parameters it
/// sent, `local`, before a RESET_STREAM_AT frame is taken; parameters not
/// sent yet announce nothing.
///
/// # Errors
///
/// [`ConnectionError::NotAnnounced`] if it did not.
fn check_announced<R>(
    local: &LocalTransportParameters<PartSlots<Part>>,
) -> Result<(), ConnectionError<R>> {
    let announced = local
        .sent()
        .is_some_and(|slots| Selector::<Option<ResetStreamAt>, _>::get(slots).is_some());
    ensure!(announced, NotAnnouncedSnafu);
    Ok(())
}

/// A RESET_STREAM_AT frame goes to the stream set of the established layer,
/// with the handle of the send strategy's intake the connection node keeps,
/// once this side's parameters as sent show that it announced
/// `reset_stream_at`; the kind of the frame was checked against the packet
/// and the role, as every frame's is, before.
///
/// Without an established layer the frame is ignored once the record of why
/// the connection closed is written, as version 1's frames of streams are.
impl<T, L, Il, Ir, Is, Ii, Idx> FrameDispatch<T, L, (Il, Ir, Is, Ii, Idx)> for Part
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    SendTypes<T, L>: SendStrategyTypes
        + IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    StreamsOf<T, L>: ResetStreamAtSet<
            CloseCauseOf<T, L>,
            StreamIntentTicketOf<T, L>,
            StreamResetsOfParts<L>,
            SendParameters = T::SendParameters,
        > + 'static,
    StreamIntentTicketOf<T, L>: IntentTicketResize + IntentTicketWithdraw,
    IntakeOf<T, L>: SendIntentIntake<AnyActiveLinkPath>
        + SharedPublishTo<StreamIntent<T::SendParameters>, AnyActiveLinkPath, Idx>,
    StreamIntentHandleOf<T, L, Idx>:
        StreamIntentHandle<T::SendParameters, StreamIntentTicketOf<T, L>>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LocalTransportParameters<PartSlots<Part>>, Il>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<SendStrategyIntake<IntakeOf<T, L>>, Ii>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![StreamsOf<T, L>], Is>,
{
    fn dispatch<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        run: ResetStreamAtFrame,
        _: &DispatchFacts<InstantOf<T>, LinkPathIdentifierOf<T, L>>,
    ) -> Result<(), ResetStreamAtConnectionErrorOf<L>> {
        check_announced(lineage.get::<LocalTransportParameters<PartSlots<Part>>, Il>())?;
        let Some(hlist_pat![streams]) = others.borrow_established::<HList![StreamsOf<T, L>], Is>()
        else {
            if lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
                .is_written()
            {
                return Ok(());
            }
            debug_assert!(
                false,
                "a RESET_STREAM_AT frame arrived without an established layer"
            );
            return NoEstablishedLayerSnafu.fail();
        };
        let publish = lineage
            .get::<SendStrategyIntake<IntakeOf<T, L>>, Ii>()
            .intake()
            .handle::<StreamIntent<T::SendParameters>, Idx>();
        streams
            .on_reset_stream_at(&publish, run)
            .context(StreamSetSnafu)
    }

    fn fields_error(
        error: ReadResetStreamAtFrameError<Infallible>,
    ) -> ResetStreamAtConnectionErrorOf<L> {
        ConnectionError::ReadFrameFields { source: error }
    }
}

#[cfg(test)]
mod tests;
