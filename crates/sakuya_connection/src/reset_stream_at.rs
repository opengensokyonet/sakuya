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
//!   when the connection is made (its `Args`,
//!   [`ResetStreamAtConnectionArgs`]). A composition with the part need not
//!   announce it. A value of the peer's that is not empty closes the
//!   connection with TRANSPORT_PARAMETER_ERROR (§3). A server that resumes
//!   a connection settles it by the composition's policy
//!   ([`ResetStreamAtChoices::ResumedParametersPolicy`]); accepting 0-RTT,
//!   it does not leave out a parameter it remembers (§3). A client whose
//!   0-RTT was accepted without the remembered parameter closes the
//!   connection with PROTOCOL_VIOLATION
//!   ([`ConnectionError::ZeroRttExtensionDisabled`]).
//! - **Sending.** A stream writer resets at a reliable size only when the
//!   peer announced the parameter: the stream set takes what the peer
//!   allows from the peer's parameters when it is made
//!   ([`PeerResetSupportSlots`]), and otherwise the reset fails with
//!   [`ResetAtError::NotSupportedByPeer`]; no RESET_STREAM_AT is sent then.
//!   A client's early layer is made on the remembered parameters and takes
//!   the server's of this handshake once they are known (RFC 9000 §7.4.1):
//!   a server that announces the parameter only now allows the resets from
//!   then on.
//! - **Receiving.** A RESET_STREAM_AT that arrives when this side did not
//!   announce the parameter closes the connection with
//!   FRAME_ENCODING_ERROR before the stream it names is looked for: for
//!   this connection it is a frame of a type it does not know (RFC 9000
//!   §12.4). Otherwise the stream set takes it as the reset kind's frame
//!   ([`StreamSet::on_reset_frame`]). A
//!   reset that changes the error code of an earlier one of the stream,
//!   RESET_STREAM as well as RESET_STREAM_AT, closes the connection with
//!   STREAM_STATE_ERROR (§5.2).
//!
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html

use core::borrow::Borrow;

use bytes::{Buf, Bytes};
use frunk_core::hlist_pat;
use nitori_io::SplitTo;
use nitori_tls::extension::alpn::ProtocolName;
use sakuya_stream::receive::violation::ResetStreamViolation;
use sakuya_stream::reset_stream_at::{receive::ResetStreamAtReceiver, send::ResetStreamAtSender};
use sakuya_stream::{
    connection::LayerEndedError,
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::ConnectionSendFlowController,
    receive::{
        StreamReceiver, flow_control::ReceiveFlowControlPolicy,
        termination::ReceiveTerminationPolicy,
    },
    receive_buffer::StreamReceiveBuffer,
    reset_stream_at::{
        receive::{OnResetStreamError, RemoteResetAt},
        send::{self, LocalResetAt, PeerResetStreamAtSupport},
    },
    send::{
        StreamSender, finish::ResetError, flow_control::SendFlowControlPolicy,
        termination::ResetOnAbandonTermination, termination::SendTerminationPolicy,
    },
    send_buffer::{SendMarker, StreamSendBuffer},
    send_options::urgency::SendUrgency,
    stream_id_ledger::ReceivingPartFrameType,
};
use sakuya_wire::{
    parameters::{ParametersPart, TrailingBytesError},
    parts::{Coprod, Coproduct, HList, HNil, PartsError, Selector},
    reset_stream_at::{
        FrameType, ResetStreamAt, ResetStreamAtFrame,
        codec::{self, ReadResetStreamAtFrameError},
    },
    v1::{
        application_error::ApplicationErrorCode,
        frame::{
            reset_stream::ResetStreamFrame,
            set::{FrameFieldsError, FrameSetPart, FrameTypeValues},
        },
        stream_id::StreamId,
        transport_error::TransportErrorCode,
        transport_parameters::TransportParameterSpace,
    },
    var_int::VarInt,
};
use snafu::{ResultExt, Snafu, ensure};

use crate::v1::SendParametersOf;
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::LineageOf,
    dispatch::{DispatchFacts, FrameDispatch},
    driver::LendNode,
    error::{ConnectionErrorPart, ConnectionErrorsOf, TransportParameterValueErrorPart},
    frame_source::{EstablishedSourceComponentsPart, FrameSourcePart, PacketKind},
    layer::{self, LogicalPath},
    others::OtherNodes,
    send_strategy::{AnyActiveLinkPath, IntentPublisher, SendIntentPart},
    share::{
        FlatMut, LayerShare, LineageLists, LineagePartList, LinkPathIdentifierOf,
        LogicalPathKeyShare, NodeData, RemainsOf,
    },
    shared::SharedConnection,
    take::{GetAt, TakeEach},
    v1::{
        Choices, CloseCauseOf, HostOf, StreamSetFamilyOf,
        application_handles::{
            connection::{ConnectionHandleRemainsOf, ConnectionHandleStateOf},
            credential::{CredentialPointer, HandleCredential},
            shared_stream::{HeldSetTakes, SharedStreamSend},
            stream::{StreamWrite, StreamWriter},
        },
        close::{CloseReasonRecord, TransportClose},
        events::SharedEvents,
        parameters::{
            AcceptedZeroRttParametersPart, ConfigureLocalTransportParametersPart, InNode,
            LocalTransportParameters, PartResumedParametersPolicy, PartSlots,
            ResumeLocalTransportParametersPart, ResumedParametersPolicy, UseConfiguredParameters,
            resume_part,
        },
        send::SendTypes,
        send_planning::{
            ComponentPublishing, HostSendStrategyTypes, PublisherOf, SendStrategyPublisher,
            StrategyPublisherFor,
        },
        streams::{
            StreamSet, StreamSetFrameError, StreamsOf,
            locked::application::LockedStreamSendShare,
            resets::{
                OnResetStreamErrorOf, PeerResetSupportSlots, StreamResets, StreamResetsOf,
                StreamResetsOfParts, StreamResetsPart,
            },
            send::StreamIntent,
        },
    },
};

/// The reliable stream reset extension, one part of a composition.
///
/// What the part is given when the connection is made, its `Args`, is a
/// [`ResetStreamAtConnectionArgs`]: the slots of its transport parameter,
/// as it sends them, and the policy of the parameter on resumption.
#[derive(Debug)]
pub struct Part;

/// What the host chooses for the extension, on its own type: the type
/// that is its choices for version 1 ([`HostOf`]). A composition with the
/// extension has choices `T` with `T: Choices<Host: ResetStreamAtChoices>`.
pub trait ResetStreamAtChoices: 'static {
    /// What decides, for a connection a server resumes, how the
    /// extension's transport parameter goes
    /// ([`ResumedParametersPolicy`]); the default sends it as configured.
    type ResumedParametersPolicy: ResumedParametersPolicy<PartSlots<Part>> + Clone + 'static =
        UseConfiguredParameters;
}

/// The extension's policy of its transport parameter on resumption, of the
/// choices `T`.
pub type ResetStreamAtResumedParametersPolicyOf<T> =
    <HostOf<T> as ResetStreamAtChoices>::ResumedParametersPolicy;

/// What the extension is given when the connection is made
/// (`ResetStreamAtConnectionArgs`): its transport parameter as this side
/// sends it, and the policy `R` of the parameter on resumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetStreamAtConnectionArgs<R = UseConfiguredParameters> {
    /// The slots of the extension's transport parameter:
    /// `hlist![Some(ResetStreamAt)]` announces `reset_stream_at`, which is
    /// what a composition with the part is for, and `hlist![None]` leaves
    /// it out.
    pub transport_parameters: PartSlots<Part>,
    /// What decides how the transport parameter goes when a server resumes
    /// a connection; a client does not use it.
    pub resumed_parameters_policy: R,
}

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
    type ResetFrame = ResetStreamAtFrame;
    type ResetRequest = ResetStreamAtRequest;
    type ResetRequestError<Lc> = ResetAtError<Lc>;

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

    fn reset_frame_stream_id(frame: &ResetStreamAtFrame) -> StreamId {
        frame.stream_id().get()
    }

    fn reset_frame_type(_: &ResetStreamAtFrame) -> ReceivingPartFrameType {
        ReceivingPartFrameType::Extension(VarInt::from_u32(RESET_STREAM_AT_FRAME_TYPE))
    }

    fn on_reset_frame<C, Lc>(
        receiver: &mut StreamReceiver<C, Lc, RemoteResetAt>,
        frame: ResetStreamAtFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError>
    where
        C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<RemoteResetAt>,
    {
        receiver.on_reset_stream_at(frame, connection)
    }

    /// The reset fails with [`ResetAtError::NotSupportedByPeer`] before the
    /// sending part sees it when the peer did not announce
    /// `reset_stream_at`.
    fn reset_with<C, K, Lc, B, M>(
        sender: &mut StreamSender<C, K, Lc, LocalResetAt, B, M>,
        support: Option<PeerResetStreamAtSupport>,
        request: ResetStreamAtRequest,
    ) -> Result<(), ResetAtError<Lc>>
    where
        K: ConnectionSendFlowController,
        M: SendMarker,
        C: StreamSendBuffer<B, K::Reservation, M>
            + SendFlowControlPolicy<LocalResetAt>
            + SendTerminationPolicy<LocalResetAt>,
    {
        let Some(support) = support else {
            return NotSupportedByPeerSnafu.fail();
        };
        sender.reset_at(support, request.code, request.reliable_size)?;
        Ok(())
    }
}

/// A reset at a reliable size, as a stream writer asks for it
/// ([`StreamResetAt::reset_at`]): the request of the extension's reset kind
/// (`ResetStreamAtRequest`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetStreamAtRequest {
    /// The application error code of the reset.
    pub code: ApplicationErrorCode,
    /// How many of the stream's first bytes are still delivered reliably.
    pub reliable_size: VarInt,
}

/// The peer allows RESET_STREAM_AT when its parameters hold
/// `reset_stream_at`.
impl<S, I> PeerResetSupportSlots<S, I> for ReliableStreamResets
where
    S: Selector<Option<ResetStreamAt>, I>,
{
    fn peer_reset_support(slots: &S) -> Option<PeerResetStreamAtSupport> {
        Selector::<Option<ResetStreamAt>, I>::get(slots)
            .map(PeerResetStreamAtSupport::from_peer_parameter)
    }
}

/// The streams of the composition reset reliably.
impl StreamResetsPart for Part {
    type Fold<Prev: StreamResets> = ReliableStreamResets;
}

// ---- the frames written ----

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
    /// The sending part's [`send::ResetAtError::LayerEnded`] once the layer
    /// ended, then [`ResetAtError::NotSupportedByPeer`], then the sending
    /// part's other [`send::ResetAtError`]s; nothing changes then.
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

/// A layer that ended is the sending part's failure.
impl<C> From<LayerEndedError<C>> for ResetAtError<C> {
    fn from(ended: LayerEndedError<C>) -> Self {
        Self::Stream {
            source: ended.into(),
        }
    }
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

/// A share of a locked stream set resets at a reliable size with what the
/// peer's parameters allow, those of this handshake once they are known
/// ([`LockedStreamSendShare::reset_with`]).
impl<Lc, K, P, H, E, C> StreamResetAt
    for LockedStreamSendShare<Lc, K, ReliableStreamResets, P, H, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer,
{
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<Lc>> {
        self.reset_with(ResetStreamAtRequest {
            code,
            reliable_size,
        })
    }
}

/// A writer through the shared connection resets at a reliable size
/// through the stream set, whatever it is ([`SharedStreamSend::reset_with`]).
impl<T, L, S, C, Ie, Ic, Ir, Is, In, I> StreamResetAt
    for SharedStreamSend<T, L, S, (Ie, Ic, Ir, Is, In, I), C>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    StreamResetsOfParts<L>: StreamResets<
            ResetRequest = ResetStreamAtRequest,
            ResetRequestError<CloseCauseOf<T, L>> = ResetAtError<CloseCauseOf<T, L>>,
        >,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer + Borrow<HandleCredential>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            SendParameters = SendParametersOf<T>,
        >,
    PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
{
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<CloseCauseOf<T, L>>> {
        self.reset_with(ResetStreamAtRequest {
            code,
            reliable_size,
        })
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
        source: ReadResetStreamAtFrameError,
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
    /// A server accepted this client's 0-RTT without the `reset_stream_at`
    /// the ticket remembers, which it must keep (PROTOCOL_VIOLATION, §3):
    /// the client may already have reset at a reliable size in 0-RTT.
    #[snafu(display("0-RTT accepted without the remembered reset_stream_at"))]
    ZeroRttExtensionDisabled,
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
            Self::ZeroRttExtensionDisabled => TransportErrorCode::PROTOCOL_VIOLATION,
            Self::ParameterValue { .. } => TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        }
    }

    fn frame_type(&self) -> Option<VarInt> {
        match self {
            Self::NotAnnounced
            | Self::ReadFrameFields { .. }
            | Self::StreamSet { .. }
            | Self::NoEstablishedLayer => Some(VarInt::from_u32(RESET_STREAM_AT_FRAME_TYPE)),
            Self::ZeroRttExtensionDisabled | Self::ParameterValue { .. } => None,
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

    fn intent_item(intent: &sakuya_wire::parts::CNil) -> sakuya_wire::parts::CNil {
        match *intent {}
    }
}

/// The extension has no content of its own to send.
impl<T: crate::clock::ConnectionChoices, L: crate::share::LogicalPathKeys, V>
    crate::frame_source::DriverContentPart<T, L, V, ()> for Part
{
    fn pending<J>(
        _: &crate::take::Lineage<'_, V>,
        _: &crate::share::LinkPathIdentifierOf<T, L>,
        _: &mut crate::send_strategy::DriverContent<J>,
        _: impl Fn(sakuya_wire::parts::CNil) -> J,
    ) {
    }
}

/// The extension has no frame source of its own.
impl<T, L> EstablishedSourceComponentsPart<T, L> for Part {
    type Components = HNil;
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
/// side sends them and their policy on resumption, made from the part's
/// `Args`.
impl<T: Choices<Host: ResetStreamAtChoices>, L> LayerShare<T, L, layer::Connection> for Part {
    type Data = HList![
        LocalTransportParameters<Part>,
        PartResumedParametersPolicy<Part, ResetStreamAtResumedParametersPolicyOf<T>>
    ];
    type Calls = HNil;
    type Args = ResetStreamAtConnectionArgs<ResetStreamAtResumedParametersPolicyOf<T>>;
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

/// The extension's transport parameter starts as configured, and its
/// policy on resumption is the one the connection was made with.
impl<T: Choices<Host: ResetStreamAtChoices>, L> ConfigureLocalTransportParametersPart<T, L>
    for Part
{
    type ResumedParametersPolicy = ResetStreamAtResumedParametersPolicyOf<T>;

    fn configured(
        args: &ResetStreamAtConnectionArgs<Self::ResumedParametersPolicy>,
    ) -> PartSlots<Self> {
        args.transport_parameters
    }

    fn resumed_parameters_policy(
        args: &ResetStreamAtConnectionArgs<Self::ResumedParametersPolicy>,
    ) -> Self::ResumedParametersPolicy {
        args.resumed_parameters_policy.clone()
    }
}

/// Whether `sent` keeps `reset_stream_at` when it is `remembered`: a
/// server that accepts 0-RTT must not leave it out (§3).
fn reset_stream_at_kept(remembered: &PartSlots<Part>, sent: &PartSlots<Part>) -> bool {
    remembered.head.is_none() || sent.head.is_some()
}

/// The extension holds to its parameter: sending the configured one, it
/// accepts 0-RTT only when it does not leave out a `reset_stream_at` that
/// was remembered (§3).
impl<V, I, Ip, Pol> ResumeLocalTransportParametersPart<V, InNode<(I, Ip, Pol)>> for Part
where
    V: GetAt<LocalTransportParameters<Part>, I> + GetAt<PartResumedParametersPolicy<Part, Pol>, Ip>,
    Pol: ResumedParametersPolicy<PartSlots<Part>>,
{
    fn resume_local(
        lineage: &mut crate::take::Lineage<'_, V>,
        remembered: &Bytes,
        application_protocol: Option<&ProtocolName<Bytes>>,
    ) -> bool {
        resume_part::<Self, V, I, Ip, Pol>(
            lineage,
            remembered,
            application_protocol,
            reset_stream_at_kept,
        )
    }
}

/// A client whose 0-RTT the server accepted checks that the server kept a
/// `reset_stream_at` the ticket remembers, as §3 has it: one left out is
/// [`ConnectionError::ZeroRttExtensionDisabled`]. One announced only in
/// this handshake is no failure, and allows the resets once the server's
/// parameters are known.
impl<L, S, J> AcceptedZeroRttParametersPart<L, S, (J,)> for Part
where
    L: StreamResetsOf,
    S: Selector<Option<ResetStreamAt>, J>,
{
    fn check_accepted(
        remembered: &S,
        received: &S,
    ) -> Result<(), ResetStreamAtConnectionErrorOf<L>> {
        let announced = |slots: &S| Selector::<Option<ResetStreamAt>, J>::get(slots).is_some();
        ensure!(
            !announced(remembered) || announced(received),
            ZeroRttExtensionDisabledSnafu
        );
        Ok(())
    }
}

// ---- the frames received ----

/// The extension reads its frames as the wire format's part.
impl FrameSetPart for Part {
    type Run<D> = ResetStreamAtFrame;
    type Kind = FrameType;
    type TypeValue = FrameType;
    type FieldsError = codec::ReadResetStreamAtFrameError;

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

    fn read_run<S: Buf + SplitTo>(
        source: &mut S,
        type_value: FrameType,
    ) -> Result<ResetStreamAtFrame, codec::ReadResetStreamAtFrameError> {
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
fn check_announced<R>(local: &LocalTransportParameters<Part>) -> Result<(), ConnectionError<R>> {
    let announced = local
        .sent()
        .is_some_and(|slots| Selector::<Option<ResetStreamAt>, _>::get(slots).is_some());
    ensure!(announced, NotAnnouncedSnafu);
    Ok(())
}

/// A RESET_STREAM_AT frame goes to the stream set of the established layer,
/// lent the send strategy's publisher the connection node keeps, once this
/// side's parameters as sent show that it announced
/// `reset_stream_at`; the kind of the frame was checked against the packet
/// and the role, as every frame's is, before.
///
/// Without an established layer the frame is ignored once the record of why
/// the connection closed is written, as version 1's frames of streams are.
impl<T, L, Il, Ir, Is, Ii, Idx> FrameDispatch<T, L, (Il, Ir, Is, Ii, Idx)> for Part
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    StreamResetsOfParts<L>: StreamResets<ResetFrame = ResetStreamAtFrame>,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            SendParameters = SendParametersOf<T>,
        > + 'static,
    PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, Idx>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LocalTransportParameters<Part>, Il>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<SendStrategyPublisher<PublisherOf<T, L>>, Ii>,
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
        check_announced(lineage.get::<LocalTransportParameters<Part>, Il>())?;
        let Some(hlist_pat![mut streams]) =
            others.borrow_established::<HList![StreamsOf<T, L>], Is>()
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
        let (taken, changed) = {
            let mut publisher = lineage.get_mut::<SendStrategyPublisher<PublisherOf<T, L>>, Ii>();
            let taken = streams.on_reset_frame::<Idx, _>(publisher.publisher_mut(), run);
            (taken, publisher.take_changed())
        };
        if let Some(changed) = changed {
            lineage.publish(changed);
        }
        taken.context(StreamSetSnafu)
    }

    fn fields_error(error: ReadResetStreamAtFrameError) -> ResetStreamAtConnectionErrorOf<L> {
        ConnectionError::ReadFrameFields { source: error }
    }
}

#[cfg(test)]
mod tests;
