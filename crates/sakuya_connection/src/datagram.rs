//! The DATAGRAM extension ([RFC 9221]) as a part of a connection.
//!
//! With the part a connection sends and receives DATAGRAM frames: data the
//! application hands over whole, which is not retransmitted (§5.1) and not
//! flow controlled, and which may be dropped (§5).
//!
//! - **Transport parameter.** The part sends `max_datagram_frame_size`
//!   (§3) as it is configured: its share of the connection node is its own
//!   [`LocalTransportParameters`], made from the part's `Args`
//!   ([`DatagramConnectionArgs`]); by default 65535, the value §3
//!   recommends. A value of the peer's that cannot be read closes the
//!   connection with TRANSPORT_PARAMETER_ERROR.
//! - **The queues.** The established layer holds the queues of the
//!   composition's choice ([`DatagramChoices::DatagramQueues`]): what the
//!   connection gives them is fixed ([`DatagramQueues`]): the frames
//!   received with the encryption level of their packet, and the end of the
//!   layer. The default is [`locked::LockedDatagramQueues`].
//! - **Receiving.** A DATAGRAM frame that arrives when this side did not
//!   announce a `max_datagram_frame_size` other than 0, or that is larger
//!   than the one it announced, closes the connection with
//!   PROTOCOL_VIOLATION (§3); otherwise the queues take it. What a datagram
//!   received is, the application reads by the side
//!   ([`DatagramSide::Received`]): a client reads the bytes, a server a
//!   [`ServerReceivedDatagram`], which says whether it came in a 0-RTT
//!   packet.
//! - **Sending.** The application sends through a
//!   [`DatagramWriter`](application::DatagramWriter): each datagram is one
//!   send intent of its own ([`DatagramIntent`]),
//!   ranked as application data, and comes back as a ticket
//!   ([`DatagramTicket`](send::DatagramTicket)) that tells whether it was
//!   sent, acknowledged or lost. Nothing is sent when the peer did not
//!   announce support, and nothing larger than the peer's limit (§3).
//!
//! [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html

pub mod application;
pub mod locked;
pub mod send;

use core::convert::Infallible;

use bytes::{Buf, Bytes};
use frunk_core::hlist_pat;
use nitori_call::{Direct, Receiver};
use nitori_io::{Read, ReadChunk};
use sakuya_stream::{connection::LayerEnd, send_options::urgency::Urgency};
use sakuya_wire::{
    datagram::{DatagramFrame, DatagramTypeValue, FrameType, MaxDatagramFrameSize, codec},
    parameters::{KeyedParameter, ParametersOf, ParametersPart},
    parts::{Coprod, Coproduct, HList, HNil, PartsError, Selector},
    v1::{
        encryption_level::EncryptionLevel,
        frame::set::{FrameFieldsError, FrameSetPart, FrameTypeValues},
        transport_error::TransportErrorCode,
        transport_parameters::{TransportParameterSlots, TransportParameterSpace},
    },
    var_int::{VarInt, VarIntWidth},
};
use snafu::{Snafu, ensure};

use self::send::{DatagramFrames, DatagramIntent, FrameSourceId};
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent},
    dispatch::{DispatchFacts, FrameDispatch},
    error::{ConnectionErrorPart, ConnectionErrorsOf, TransportParameterValueErrorPart},
    frame_source::{
        EstablishedSourceComponentsPart, FrameSourceItemsOf, FrameSourcePart, PacketKind,
    },
    layer::{self, LogicalPath},
    others::OtherNodes,
    send_strategy::{
        AnyActiveLinkPath, IntentTicketWithdraw, PlannedPacketKind, SendIntentHandle,
        SendIntentIntake, SendIntentPart, SendStrategy,
    },
    share::{
        ConnectionArgsOf, FlatMut, LayerShare, LineageLists, LineagePartList, LinkPathIdentifierOf,
        LogicalPathKeyShare, NodeData,
    },
    take::{GetAt, TakeEach},
    v1::{
        Choices, Client, CloseCauseOf, HostOf, Server, Side,
        application_handles::{
            DriverPanicHandleShare, FindHandleShare, HandleShare, HandleShares, KeyedHandleShare,
            connection::{ConnectionHandleCellOf, EstablishedLayerSharesOf},
            handle,
        },
        close::{CloseReasonRecord, TransportClose},
        parameters::{LocalTransportParameters, PartSlots, PeerTransportParameters},
        send::SendTypes,
        send_planning::{IntakeOf, IntakePublishOutcome, SendStrategyOf},
        streams::resets::{StreamResets, StreamResetsOf, StreamResetsPart},
    },
};

/// The `max_datagram_frame_size` this side announces unless it is
/// configured otherwise: 65535, as RFC 9221 §3 recommends, so that the
/// peer's datagrams are limited by the path, not by the parameter.
pub const RECOMMENDED_MAX_DATAGRAM_FRAME_SIZE: u16 = 65535;

/// The DATAGRAM extension, one part of a composition.
///
/// What the part is given when the connection is made, its `Args`, is a
/// [`DatagramConnectionArgs`]: the slots of its transport parameter, as it
/// sends them, and the configuration of the queues of the established
/// layer.
#[derive(Debug)]
pub struct Part;

// ---- the choices ----

/// What the host chooses for the extension, on its own type: the type
/// that is its choices for version 1 ([`HostOf`]). A composition with the
/// extension has choices `T` with `T: Choices<Side: DatagramSide, Host:
/// DatagramChoices>`.
pub trait DatagramChoices: 'static {
    /// The kind of queues of the established layer.
    type DatagramQueues: DatagramQueuesFamily = locked::LockedDatagramQueuesFamily;
}

/// A kind of queues of the established layer: one queues type for each
/// `Lc`, this endpoint's reason for closing ([`CloseCauseOf`] for the
/// composition's list of parts), `K`, the ticket the send strategy's intake
/// gives back for a datagram's intent ([`DatagramTicketOf`]), and `S`, the
/// side, which gives what a datagram received is; all take the same
/// configuration.
pub trait DatagramQueuesFamily: 'static {
    /// What the composition configures the queues with; the connection
    /// node keeps it from the connection's making until the established
    /// layer is built.
    type Config: Clone + Default + 'static;
    /// The queues for `Lc`, `K` and `S`.
    type Queues<Lc, K: IntentTicketWithdraw, S: DatagramSide>: DatagramQueues<Lc, Config = Self::Config, StrategyTicket = K>;
}

/// The kind of queues the host of the choices `T` chooses.
pub type DatagramQueuesFamilyOf<T> = <HostOf<T> as DatagramChoices>::DatagramQueues;

/// The configuration of the queues of the choices `T`.
pub type DatagramQueuesConfigOf<T> = <DatagramQueuesFamilyOf<T> as DatagramQueuesFamily>::Config;

/// The ticket the send strategy's intake of the choices `T` and the list of
/// parts `L` gives back for a datagram's intent.
pub type DatagramTicketOf<T, L> =
    <SendTypes<T, L> as IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>>::Outcome;

/// The handle the intake of the choices `T` and the list of parts `L` gives
/// for the datagrams' intents, at the place `Idx`.
pub type DatagramIntentHandleOf<T, L, Idx> =
    <IntakeOf<T, L> as SendIntentIntake<AnyActiveLinkPath>>::Handle<DatagramIntent<Urgency>, Idx>;

/// The queues of the established layer of the choices `T` and the list of
/// parts `L`.
pub type DatagramQueuesOf<T, L> = <DatagramQueuesFamilyOf<T> as DatagramQueuesFamily>::Queues<
    CloseCauseOf<T, L>,
    DatagramTicketOf<T, L>,
    <T as crate::v1::MakerChoices>::Side,
>;

/// What one side reads of a datagram it received (`DatagramSide`): the
/// type, and how it is made from the frame's data and the encryption level
/// of the packet it came in.
///
/// Whether a datagram came in a 0-RTT packet matters to a server only:
/// only a client sends 0-RTT packets (RFC 9000 §17.2.3), so a client reads
/// the bytes alone. Version 1's sides implement it ([`Client`],
/// [`Server`]).
pub trait DatagramSide {
    /// What the application reads of one datagram received.
    type Received: Buf + Send + 'static;

    /// The datagram of `data`, which came in a packet of `level`.
    fn received(level: EncryptionLevel, data: Bytes) -> Self::Received;
}

/// A client reads the bytes.
impl<Tls, Tk, Rp> DatagramSide for Client<Tls, Tk, Rp>
where
    Client<Tls, Tk, Rp>: Side,
{
    type Received = Bytes;

    fn received(_: EncryptionLevel, data: Bytes) -> Bytes {
        data
    }
}

/// A server reads whether the datagram came in a 0-RTT packet, which may
/// be replayed (RFC 9001 §9.2), as well.
impl<Tls> DatagramSide for Server<Tls>
where
    Server<Tls>: Side,
{
    type Received = ServerReceivedDatagram;

    fn received(level: EncryptionLevel, data: Bytes) -> ServerReceivedDatagram {
        ServerReceivedDatagram {
            data,
            zero_rtt: level == EncryptionLevel::ZeroRtt,
        }
    }
}

/// A datagram a server received (`ServerReceivedDatagram`): its bytes, read
/// as a [`Buf`], and whether it came in a 0-RTT packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerReceivedDatagram {
    data: Bytes,
    zero_rtt: bool,
}

impl ServerReceivedDatagram {
    /// Whether the datagram came in a 0-RTT packet, which an attacker may
    /// replay (RFC 9001 §9.2). A server that takes no 0-RTT data receives
    /// none there, so it is `false` for every datagram.
    pub fn received_zero_rtt(&self) -> bool {
        self.zero_rtt
    }

    /// The bytes not read yet.
    pub fn into_bytes(self) -> Bytes {
        self.data
    }
}

impl Buf for ServerReceivedDatagram {
    fn remaining(&self) -> usize {
        self.data.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.data.chunk()
    }

    fn advance(&mut self, count: usize) {
        self.data.advance(count);
    }
}

// ---- the queues ----

/// The queues of the established layer (`DatagramQueues`): a bounded queue
/// of the datagrams received and one of the datagrams to send. This is what
/// the connection gives them; what the application asks of them is the
/// capability their handle gives ([`application::Datagrams`]).
///
/// `Lc` is this endpoint's reason for closing, which the layer's end
/// carries.
pub trait DatagramQueues<Lc>: Sized {
    /// What the composition configures them with.
    type Config;
    /// The share of the queues the application's handles hold: the
    /// extension's share of an established layer's handle, which publishes
    /// the datagrams through the handle's intake.
    ///
    /// When the driver panicked, the connection handle's cell tells it the
    /// layer's end ([`DriverPanicHandleShare::driver_panicked`]) instead of
    /// [`layer_ended`](Self::layer_ended), which is never called then: it
    /// only marks the end, where every receive and send and every ticket of
    /// a datagram that waits to be sent looks first, and wakes who waits to
    /// receive and who waits for those tickets to settle. It neither
    /// withdraws the datagrams nor touches the strategy's tickets, as it may
    /// run while the panic unwinds.
    type Handle: Clone + KeyedHandleShare<Part = Part> + DriverPanicHandleShare<Lc>;
    /// The ticket the send strategy gives back for a datagram's intent.
    type StrategyTicket;

    /// The queues of a layer just built, of the facts `facts` and
    /// configured by `config`.
    fn new(facts: DatagramQueuesFacts, config: Self::Config) -> Self;

    /// The share of the queues.
    fn handle(&self) -> Self::Handle;

    /// A DATAGRAM frame arrived in a packet of `level`, no larger than this
    /// side announced. It cannot be refused: what the queues cannot keep
    /// they drop (RFC 9221 §5).
    fn on_datagram_frame(&mut self, level: EncryptionLevel, frame: DatagramFrame<Bytes>);

    /// The established layer ended as `end`: what was received is still
    /// read first, then every read and send reports the end.
    fn layer_ended(&mut self, end: LayerEnd<Lc>);

    /// The datagrams waiting whose intents were not fulfilled go on as
    /// their destinations say, now: published again through `publish` while
    /// the destination degrades, withdrawn once it has nothing left. What
    /// was written or withdrawn meanwhile leaves the send queue.
    ///
    /// The DATAGRAM frame source calls it when an intent of it was not
    /// fulfilled, so that the datagram's ticket does not wait for the next
    /// send to hear of it.
    fn resolve_unfulfilled<H>(&mut self, publish: &H)
    where
        H: SendIntentHandle<
                DatagramIntent<Urgency>,
                AnyActiveLinkPath,
                Outcome = Self::StrategyTicket,
            >;
}

/// What the queues of a layer are made from (`DatagramQueuesFacts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DatagramQueuesFacts {
    /// The peer's `max_datagram_frame_size` as received; 0 when the peer
    /// did not send it, or its parameters are not known when the layer is
    /// built: it takes no DATAGRAM frames then.
    pub peer: MaxDatagramFrameSize,
}

/// What a queue does when it is full and one more datagram comes
/// (`DatagramOverflow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DatagramOverflow {
    /// The new one is not taken: a send fails with
    /// [`SendDatagramError::QueueFull`](application::SendDatagramError::QueueFull),
    /// a datagram received is dropped.
    #[default]
    RejectNew,
    /// The oldest ones go to make room: a datagram to send is withdrawn,
    /// and its ticket says so; a datagram received is dropped.
    DropOldest,
}

/// The largest datagram that fits into a DATAGRAM frame with a Length
/// field of at most `limit` bytes, in bytes of data; `None` when no data,
/// not even none, fits: the limit is below 2 bytes, the Frame Type and an
/// empty Length field.
///
/// The limit is counted with the Length field, whatever frame is written:
/// a frame written last in its packet may leave it out, so the limit holds
/// either way.
pub(crate) fn payload_limit(limit: MaxDatagramFrameSize) -> Option<usize> {
    let limit = usize::try_from(limit.get().get()).unwrap_or(usize::MAX);
    [
        VarIntWidth::One,
        VarIntWidth::Two,
        VarIntWidth::Four,
        VarIntWidth::Eight,
    ]
    .into_iter()
    .filter_map(|width| {
        let len = limit.checked_sub(1 + width.encoded_len())?;
        let shortest = VarIntWidth::shortest(VarInt::try_from(len).ok()?);
        (shortest.encoded_len() <= width.encoded_len()).then_some(len)
    })
    .max()
}

/// The length of a DATAGRAM frame with a Length field of the shortest
/// width and `len` bytes of data.
pub(crate) fn frame_len_with_length(len: usize) -> usize {
    let width = VarIntWidth::shortest(VarInt::try_from(len).unwrap_or(VarInt::MAX));
    1 + width.encoded_len() + len
}

// ---- the error ----

/// An error of the extension in a connection: one variant for each kind of
/// failure, each with the transport error code it closes with.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ConnectionError {
    /// A DATAGRAM frame arrived, though this side did not announce a
    /// `max_datagram_frame_size` other than 0 (PROTOCOL_VIOLATION, RFC 9221
    /// §3).
    #[snafu(display("DATAGRAM frame without max_datagram_frame_size announced"))]
    NotAnnounced {
        /// Whether the frame had a Length field (type `0x31`).
        has_length: bool,
    },
    /// A DATAGRAM frame is larger than the `max_datagram_frame_size` this
    /// side announced (PROTOCOL_VIOLATION, RFC 9221 §3).
    #[snafu(display("DATAGRAM frame of {frame_len} bytes over the announced {limit:?}"))]
    FrameTooLarge {
        /// Whether the frame had a Length field (type `0x31`).
        has_length: bool,
        /// The length of the frame: its Frame Type, Length and data.
        frame_len: usize,
        /// What this side announced.
        limit: MaxDatagramFrameSize,
    },
    /// The fields of a DATAGRAM frame could not be read.
    #[snafu(display("DATAGRAM frame fields read failed"))]
    ReadFrameFields {
        /// The failure.
        source: codec::ReadDatagramFrameError<Infallible>,
    },
    /// A DATAGRAM frame arrived while the connection has no established
    /// layer and is not closing; the connection closes with INTERNAL_ERROR.
    /// It does not happen, as for version 1's frames of streams.
    #[snafu(display("DATAGRAM frame without an established layer"))]
    NoEstablishedLayer {
        /// Whether the frame had a Length field (type `0x31`).
        has_length: bool,
    },
    /// The peer's `max_datagram_frame_size` could not be read
    /// (TRANSPORT_PARAMETER_ERROR).
    #[snafu(display("max_datagram_frame_size value rejected"))]
    ParameterValue {
        /// The failure of reading the value.
        source: <MaxDatagramFrameSize as KeyedParameter>::ValueError,
    },
}

/// The Frame Type value of a DATAGRAM frame: `0x31` with a Length field,
/// `0x30` without.
fn datagram_frame_type(has_length: bool) -> VarInt {
    VarInt::from_u32(if has_length { 0x31 } else { 0x30 })
}

/// The Frame Type field holds the DATAGRAM frame's type for a failure of a
/// frame; the reason phrase is what this layer shows, without its sources.
impl TransportClose for ConnectionError {
    fn code(&self) -> TransportErrorCode {
        match self {
            Self::NotAnnounced { .. } | Self::FrameTooLarge { .. } => {
                TransportErrorCode::PROTOCOL_VIOLATION
            }
            Self::ReadFrameFields { source } => source.transport_error_code(),
            Self::NoEstablishedLayer { .. } => TransportErrorCode::INTERNAL_ERROR,
            Self::ParameterValue { .. } => TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
        }
    }

    fn frame_type(&self) -> Option<VarInt> {
        match self {
            Self::NotAnnounced { has_length }
            | Self::FrameTooLarge { has_length, .. }
            | Self::NoEstablishedLayer { has_length } => Some(datagram_frame_type(*has_length)),
            Self::ReadFrameFields { source } => Some(source.frame_type()),
            Self::ParameterValue { .. } => None,
        }
    }

    fn reason_phrase(&self) -> Bytes {
        Bytes::from(self.to_string())
    }
}

impl<L> ConnectionErrorPart<L> for Part {
    type ConnectionError = ConnectionError;
}

/// The failures of the value of `max_datagram_frame_size`, the one
/// parameter of the extension.
type ParameterValueErrors = Coprod![<MaxDatagramFrameSize as KeyedParameter>::ValueError];

/// The one parameter of the extension is one variable-length integer.
impl<L> TransportParameterValueErrorPart<ParameterValueErrors, L> for Part {
    fn value_error(id: VarInt, source: PartsError<ParameterValueErrors>) -> ConnectionError {
        debug_assert_eq!(
            id,
            <MaxDatagramFrameSize as KeyedParameter>::ID,
            "the extension has one parameter"
        );
        let PartsError(Coproduct::Inl(source)) = source;
        ConnectionError::ParameterValue { source }
    }
}

// ---- the part's shares ----

/// The extension leaves how streams are reset as it is.
impl StreamResetsPart for Part {
    type Fold<Prev: StreamResets> = Prev;
}

/// The extension adds nothing to the key of a logical path.
impl LogicalPathKeyShare for Part {
    type Fields = HNil;
}

/// The transport parameters of the extension are those its wire format
/// defines.
impl ParametersPart<TransportParameterSpace> for Part {
    type Parameters =
        <sakuya_wire::datagram::Part as ParametersPart<TransportParameterSpace>>::Parameters;
}

/// One intent for each datagram, which the DATAGRAM frames write.
impl SendIntentPart for Part {
    type FrameSourceId = FrameSourceId;
    type SendIntents = Coprod![DatagramIntent<Urgency>];
    type FrameSources = HList![DatagramFrames];

    fn intent_item(intent: &Coprod![DatagramIntent<Urgency>]) -> FrameSourceItemsOf<'_, Self> {
        match intent {
            Coproduct::Inl(intent) => Coproduct::Inl(intent),
            Coproduct::Inr(never) => match *never {},
        }
    }
}

/// DATAGRAM frames go in 0-RTT and 1-RTT packets of an active link path,
/// as the frames of streams do; they are not probing frames, so a
/// candidate's packets do not carry them.
impl<K: PacketKind> FrameSourcePart<K> for Part {
    fn item(intent: &Coprod![DatagramIntent<Urgency>]) -> Option<FrameSourceItemsOf<'_, Self>> {
        matches!(
            K::KIND,
            PlannedPacketKind::ZeroRtt | PlannedPacketKind::OneRtt
        )
        .then(|| <Self as SendIntentPart>::intent_item(intent))
    }

    fn source(item: &FrameSourceItemsOf<'_, Self>) -> FrameSourceId {
        match item {
            Coproduct::Inl(_) => FrameSourceId::Datagram,
            Coproduct::Inr(never) => match *never {},
        }
    }
}

/// What the extension is given when the connection is made
/// (`DatagramConnectionArgs`): its transport parameter as this side sends
/// it, and the configuration `C` of the queues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramConnectionArgs<C> {
    /// The slots of the extension's transport parameter:
    /// `hlist![Some(MaxDatagramFrameSize)]` announces it, `hlist![None]` or
    /// a size of 0 leaves the extension off for the peer.
    pub transport_parameters: PartSlots<Part>,
    /// What the queues of the established layer are configured with.
    pub queues: C,
}

/// The recommended `max_datagram_frame_size`, and the default queues.
impl<C: Default> Default for DatagramConnectionArgs<C> {
    fn default() -> Self {
        Self {
            transport_parameters: frunk_core::hlist![Some(MaxDatagramFrameSize::new(
                VarInt::from(RECOMMENDED_MAX_DATAGRAM_FRAME_SIZE)
            ))],
            queues: C::default(),
        }
    }
}

/// The configuration of the queues, `C`, kept in the connection node until
/// the established layer is built.
#[derive(Debug)]
pub struct DatagramQueuesConfig<C>(pub C);

/// It has no deadline and reads nothing; the queues are made from it.
impl<C> PassiveDataComponent for DatagramQueuesConfig<C> {}

/// The connection node keeps the extension's transport parameters as this
/// side sends them, and the configuration of the queues, both from the
/// part's `Args`.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L> LayerShare<T, L, layer::Connection>
    for Part
{
    type Data = HList![
        LocalTransportParameters<PartSlots<Part>>,
        DatagramQueuesConfig<DatagramQueuesConfigOf<T>>
    ];
    type Calls = HNil;
    type Args = DatagramConnectionArgs<DatagramQueuesConfigOf<T>>;
}

/// The established layer holds the queues.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L: ConnectionErrorsOf>
    LayerShare<T, L, layer::Established> for Part
where
    SendTypes<T, L>: IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
    DatagramTicketOf<T, L>: IntentTicketWithdraw,
{
    type Data = HList![DatagramQueuesOf<T, L>];
    type Calls = HNil;
}

/// The handle of an established layer holds the queues' handle, to send
/// and receive datagrams with.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L: ConnectionErrorsOf>
    HandleShare<T, L, handle::EstablishedLayer> for Part
where
    SendTypes<T, L>: IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
    DatagramTicketOf<T, L>: IntentTicketWithdraw,
{
    type Share = <DatagramQueuesOf<T, L> as DatagramQueues<CloseCauseOf<T, L>>>::Handle;
}

/// The DATAGRAM frame source finds the queues of the established layer.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L: ConnectionErrorsOf>
    EstablishedSourceComponentsPart<T, L> for Part
where
    SendTypes<T, L>: IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
    DatagramTicketOf<T, L>: IntentTicketWithdraw,
{
    type Components = HList![DatagramQueuesOf<T, L>];
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
no_share!(LinkEntry, LogicalPath, LinkPath, Recovery);

/// The extension's transport parameters start as configured; the part
/// marks where they are among the components, apart from version 1's.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L, I>
    Build<T, L, layer::Connection, (Part, I)> for LocalTransportParameters<PartSlots<Part>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<DatagramConnectionArgs<DatagramQueuesConfigOf<T>>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args: &DatagramConnectionArgs<DatagramQueuesConfigOf<T>> = Selector::get(args);
        LocalTransportParameters::Configured(args.transport_parameters)
    }
}

/// The connection keeps the configuration it was made with.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L, I>
    Build<T, L, layer::Connection, (Part, I)> for DatagramQueuesConfig<DatagramQueuesConfigOf<T>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<DatagramConnectionArgs<DatagramQueuesConfigOf<T>>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args: &DatagramConnectionArgs<DatagramQueuesConfigOf<T>> = Selector::get(args);
        DatagramQueuesConfig(args.queues.clone())
    }
}

/// Where the queues are among the established layer's components.
#[derive(Debug)]
pub struct ChosenDatagramQueues;

/// The queues are made when the established layer is built, from the
/// peer's `max_datagram_frame_size` as received and the configuration the
/// connection node keeps; a layer built before the peer's parameters are
/// known takes the peer's as absent: nothing is sent.
///
/// The cell of the connection handle in the connection node is handed the
/// queues' handle, the extension's share of the layer's handle, when the
/// layer is built.
///
/// When the layer ends, the queues hear that the connection closed, for the
/// reason in the record of why the connection closed.
impl<T, L, X, Ip, Ic, Ir, Ih, Jm, Js>
    Build<T, L, layer::Established, (ChosenDatagramQueues, (Ip, Ic, Ir, Ih), (Jm, Js))> for X
where
    T: Choices<
        Side: DatagramSide,
        Host: DatagramChoices<
            DatagramQueues: DatagramQueuesFamily<
                Queues<CloseCauseOf<T, L>, DatagramTicketOf<T, L>, <T as crate::v1::MakerChoices>::Side> = X,
            >,
        >,
    >,
    L: LineagePartList<T>
        + ConnectionErrorsOf
        + ParametersOf<TransportParameterSpace>
        + HandleShares<T, L, handle::EstablishedLayer>,
    SendTypes<T, L>: IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    DatagramTicketOf<T, L>: IntentTicketWithdraw,
    X: DatagramQueues<CloseCauseOf<T, L>, Config = DatagramQueuesConfigOf<T>>,
    TransportParameterSlots<L>: Selector<Option<MaxDatagramFrameSize>, Jm>,
    EstablishedLayerSharesOf<T, L>: FindHandleShare<Part, Js, Found = X::Handle>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>
        + GetAt<DatagramQueuesConfig<DatagramQueuesConfigOf<T>>, Ic>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<ConnectionHandleCellOf<T, L>, Ih>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::Established>,
        _: &mut ArgsOf<T, L, layer::Established>,
    ) -> Self {
        let peer = parents
            .get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>()
            .known()
            .and_then(|slots| *Selector::<Option<MaxDatagramFrameSize>, Jm>::get(slots))
            .unwrap_or_default();
        let config = parents
            .get::<DatagramQueuesConfig<DatagramQueuesConfigOf<T>>, Ic>()
            .0
            .clone();
        let queues = X::new(DatagramQueuesFacts { peer }, config);
        parents
            .get::<ConnectionHandleCellOf<T, L>, Ih>()
            .share_built::<Part, Js>(queues.handle());
        queues
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
            // invariant: as for the stream set, only a written record ends
            // the established layer without 0-RTT
            None => debug_assert!(false, "the established layer ends without a reason"),
        }
    }
}

/// The queues have no deadline and read nothing: the dispatch of frames and
/// the application change them.
impl<T, L, X> DataComponent<T, L, layer::Established, ChosenDatagramQueues> for X
where
    T: Choices<
        Side: DatagramSide,
        Host: DatagramChoices<
            DatagramQueues: DatagramQueuesFamily<
                Queues<CloseCauseOf<T, L>, DatagramTicketOf<T, L>, <T as crate::v1::MakerChoices>::Side> = X,
            >,
        >,
    >,
    L: LineagePartList<T> + ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
    DatagramTicketOf<T, L>: IntentTicketWithdraw,
{
}

// ---- the frames received ----

/// The extension reads its frames as the wire format's part.
impl FrameSetPart for Part {
    type Run<D> = DatagramFrame<D>;
    type Kind = FrameType;
    type TypeValue = DatagramTypeValue;
    type FieldsError<E> = codec::ReadDatagramFrameError<E>;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        <sakuya_wire::datagram::Part as FrameSetPart>::FRAME_TYPE_VALUES;

    fn type_value_of(value: VarInt) -> Option<DatagramTypeValue> {
        <sakuya_wire::datagram::Part as FrameSetPart>::type_value_of(value)
    }

    fn kind_of(type_value: DatagramTypeValue) -> FrameType {
        <sakuya_wire::datagram::Part as FrameSetPart>::kind_of(type_value)
    }

    fn run_kind<D>(run: &DatagramFrame<D>) -> FrameType {
        <sakuya_wire::datagram::Part as FrameSetPart>::run_kind::<D>(run)
    }

    fn read_run<H>(
        source: &mut H,
        type_value: DatagramTypeValue,
    ) -> Result<
        <Self as FrameSetPart>::Run<<Direct<H> as ReadChunk>::Chunk>,
        <Self as FrameSetPart>::FieldsError<<Direct<H> as Read>::Error>,
    >
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>,
    {
        <sakuya_wire::datagram::Part as FrameSetPart>::read_run(source, type_value)
    }
}

/// Check `frame` against what this side announced in the parameters it
/// sent, `local`: a `max_datagram_frame_size` other than 0, and not
/// smaller than the frame; parameters not sent yet announce nothing.
///
/// # Errors
///
/// [`ConnectionError::NotAnnounced`] or [`ConnectionError::FrameTooLarge`].
fn check_announced<D: Buf>(
    local: &LocalTransportParameters<PartSlots<Part>>,
    frame: &DatagramFrame<D>,
) -> Result<(), ConnectionError> {
    let has_length = frame.length().is_right();
    let announced = local
        .sent()
        .and_then(|slots| *Selector::<Option<MaxDatagramFrameSize>, _>::get(slots))
        .filter(|limit| limit.get() != VarInt::ZERO);
    let Some(limit) = announced else {
        return NotAnnouncedSnafu { has_length }.fail();
    };
    let frame_len = frame.encoded_len();
    let within = u64::try_from(frame_len).is_ok_and(|len| len <= limit.get().get());
    ensure!(
        within,
        FrameTooLargeSnafu {
            has_length,
            frame_len,
            limit,
        }
    );
    Ok(())
}

/// A DATAGRAM frame goes to the queues of the established layer, with the
/// encryption level of its packet, once this side's parameters as sent show
/// that it announced support and a limit the frame keeps to (RFC 9221 §3);
/// the kind of the frame was checked against the packet and the role, as
/// every frame's is, before.
///
/// Without an established layer the frame is ignored once the record of why
/// the connection closed is written, as version 1's frames of streams are.
impl<T, L, Il, Ir, Iq> FrameDispatch<T, L, (Il, Ir, Iq)> for Part
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    SendTypes<T, L>: IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
    DatagramTicketOf<T, L>: IntentTicketWithdraw,
    DatagramQueuesOf<T, L>: DatagramQueues<CloseCauseOf<T, L>> + 'static,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LocalTransportParameters<PartSlots<Part>>, Il>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![DatagramQueuesOf<T, L>], Iq>,
{
    fn dispatch<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        run: DatagramFrame<Bytes>,
        packet: &DispatchFacts<InstantOf<T>, LinkPathIdentifierOf<T, L>>,
    ) -> Result<(), ConnectionError> {
        check_announced(
            lineage.get::<LocalTransportParameters<PartSlots<Part>>, Il>(),
            &run,
        )?;
        let has_length = run.length().is_right();
        let Some(hlist_pat![queues]) =
            others.borrow_established::<HList![DatagramQueuesOf<T, L>], Iq>()
        else {
            if lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
                .is_written()
            {
                return Ok(());
            }
            debug_assert!(
                false,
                "a DATAGRAM frame arrived without an established layer"
            );
            return NoEstablishedLayerSnafu { has_length }.fail();
        };
        queues.on_datagram_frame(packet.level(), run);
        Ok(())
    }

    fn fields_error(error: codec::ReadDatagramFrameError<Infallible>) -> ConnectionError {
        ConnectionError::ReadFrameFields { source: error }
    }
}

#[cfg(test)]
mod tests;
