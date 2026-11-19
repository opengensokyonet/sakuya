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
//!   connection with TRANSPORT_PARAMETER_ERROR. A server that resumes a
//!   connection settles it by the composition's policy
//!   ([`DatagramChoices::ResumedParametersPolicy`]); accepting 0-RTT, it
//!   sends no value lower than the one it remembers (§3).
//! - **The queues.** The established layer holds the queues of the
//!   composition's choice ([`DatagramChoices::DatagramQueues`]): what the
//!   connection gives them is fixed ([`DatagramQueues`]): the frames
//!   received with the encryption level of their packet, the frames to
//!   write and what comes of them, the operations of the application
//!   through the shared connection, and the end of the layer. The default
//!   is [`owned::OwnedDatagramQueues`], which the connection holds and only
//!   the capability through the shared connection reaches
//!   ([`shared`]); [`locked::LockedDatagramQueues`] also gives a share of
//!   its send queue held apart from the connection.
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
//!   send intent of its own ([`DatagramIntent`]), which carries the
//!   datagram's key in its queues, ranked as application data, and comes
//!   back as a ticket ([`SharedDatagramTicket`](shared::SharedDatagramTicket),
//!   or [`DatagramTicket`](send::DatagramTicket) apart from the connection)
//!   that tells whether it was sent, acknowledged or lost. Nothing is sent
//!   when the peer did not announce support, and nothing larger than the
//!   peer's limit (§3).
//!
//! [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html

pub mod application;
pub mod locked;
pub mod owned;
pub mod send;
pub mod shared;

use alloc::vec::Vec;
use core::{
    fmt,
    num::NonZeroUsize,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use frunk_core::hlist_pat;
use nitori_io::SplitTo;
use nitori_tls::extension::alpn::ProtocolName;
use sakuya_stream::{
    connection::{AbortCause, CloseReason, LayerEnd, LayerEndedError},
    send_options::{
        destination::{AnyActiveLinkPath, Unfulfilled},
        urgency::Urgency,
    },
};
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

use self::{
    application::{DatagramFrameLimits, SendDatagramError},
    send::{
        DatagramFrames, DatagramIntent, DatagramKey, DatagramSettlement, DatagramState,
        DatagramSummary, FrameSourceId, HeldDatagram, WithdrawReport,
    },
};
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent},
    dispatch::{DispatchFacts, FrameDispatch},
    error::{ConnectionErrorPart, ConnectionErrorsOf, TransportParameterValueErrorPart},
    feedback::InjectSummary,
    frame_source::{
        EstablishedSourceComponentsPart, FrameSourceItemsOf, FrameSourcePart, PacketKind,
    },
    layer::{self, LogicalPath},
    others::OtherNodes,
    send_strategy::{IntentTicketChanges, PlannedPacketKind, PublishOutcome, SendIntentPart},
    share::{
        ConnectionArgsOf, FlatMut, LayerShare, LineageLists, LineagePartList, LinkPathIdentifierOf,
        LogicalPathKeyShare, NodeData, RemainsOf,
    },
    take::{GetAt, TakeEach},
    v1::{
        Choices, Client, CloseCauseOf, EventsOf, HostOf, Server, SharedEventsOf, Side,
        application_handles::connection::{ConnectionHandleStateOf, LayerId},
        close::{CloseReasonRecord, TransportClose},
        events::{ConnectionEventSink, ConnectionEvents, SharedEvents},
        parameters::{
            AcceptedZeroRttParametersPart, InNode, LocalTransportParameters,
            PartResumedParametersPolicy, PartSlots, PeerTransportParameters,
            ResumeLocalTransportParametersPart, ResumedParametersPolicy, UseConfiguredParameters,
            resume_part,
        },
        send::SendTypes,
        send_planning::{
            ComponentIntake, ComponentPublishing, HostSendStrategyTypes, SendStrategyCore,
            SendStrategyOf, StrategyPublisherForTicket, StrategyPublisherOf,
        },
        streams::resets::{StreamResets, StreamResetsOf, StreamResetsPart},
    },
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// What locking `mutex` gives, whether or not a holder panicked: a holder
/// panics only on a broken invariant of its own, and the state is taken as
/// it was left.
pub(crate) fn lock<X>(mutex: &std::sync::Mutex<X>) -> std::sync::MutexGuard<'_, X> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
    type DatagramQueues: DatagramQueuesFamily = owned::OwnedDatagramQueuesFamily;
    /// What decides, for a connection a server resumes, how the
    /// extension's transport parameter goes
    /// ([`ResumedParametersPolicy`]); the default sends it as configured.
    type ResumedParametersPolicy: ResumedParametersPolicy<PartSlots<Part>> + Clone + 'static =
        UseConfiguredParameters;
}

/// The extension's policy of its transport parameter on resumption, of the
/// choices `T`.
pub type DatagramResumedParametersPolicyOf<T> =
    <HostOf<T> as DatagramChoices>::ResumedParametersPolicy;

/// A kind of queues of the established layer: one queues type for each
/// `Lc`, this endpoint's reason for closing ([`CloseCauseOf`] for the
/// composition's list of parts), `I`, the send strategy types the
/// datagrams' intents are published to, which give what the queues publish
/// through and the ticket they keep for an intent ([`ComponentPublishing`]),
/// `S`, the side, which gives what a datagram received is, and `E`, the
/// handle the events of the datagrams are given through
/// ([`ConnectionEvents::Shared`]);
/// all take the same configuration.
pub trait DatagramQueuesFamily: 'static {
    /// What the composition configures the queues with; the connection
    /// node keeps it from the connection's making until the established
    /// layer is built.
    type Config: Clone + Default + 'static;
    /// What the queues of the side `S` leave once their layer ended
    /// ([`DatagramQueues::Remains`]), whatever the other parameters: the
    /// connection node keeps it for each layer that ended.
    type Remains<S: DatagramSide>: 'static;
    /// The queues for `Lc`, `I`, `S` and `E`; queues that give no events
    /// may drop the handle. Version 1 asks for them to be
    /// [`DatagramQueues`] where it uses them.
    type Queues<
        Lc,
        I: ComponentPublishing<Self, DatagramIntent<Urgency>>,
        S: DatagramSide,
        E: SharedEvents + Clone + 'static,
    >;
}

/// The kind of queues the host of the choices `T` chooses.
pub type DatagramQueuesFamilyOf<T> = <HostOf<T> as DatagramChoices>::DatagramQueues;

/// The configuration of the queues of the choices `T`.
pub type DatagramQueuesConfigOf<T> = <DatagramQueuesFamilyOf<T> as DatagramQueuesFamily>::Config;

/// What the queues of an established layer of the choices `T` leave once
/// the layer ended.
pub type DatagramLayerRemainsOf<T> = <DatagramQueuesFamilyOf<T> as DatagramQueuesFamily>::Remains<
    <T as crate::v1::MakerChoices>::Side,
>;

/// What the queues of the layers of the choices `T` that ended leave, as
/// the connection node keeps it.
pub type DatagramQueuesRemainsOf<T> = DatagramQueuesRemains<DatagramLayerRemainsOf<T>>;

/// The ticket the queues of the choices `T` and the list of parts `L` keep
/// for a datagram's intent.
pub type DatagramTicketOf<T, L> = <SendTypes<T, L> as ComponentPublishing<
    DatagramQueuesFamilyOf<T>,
    DatagramIntent<Urgency>,
>>::Ticket;

/// The queues of the established layer of the choices `T` and the list of
/// parts `L`.
pub type DatagramQueuesOf<T, L> = <DatagramQueuesFamilyOf<T> as DatagramQueuesFamily>::Queues<
    CloseCauseOf<T, L>,
    SendTypes<T, L>,
    <T as crate::v1::MakerChoices>::Side,
    SharedEventsOf<T, L>,
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
impl<Tls, Tk, Rp, Lc> DatagramSide for Client<Tls, Tk, Rp, Lc>
where
    Client<Tls, Tk, Rp, Lc>: Side,
{
    type Received = Bytes;

    fn received(_: EncryptionLevel, data: Bytes) -> Bytes {
        data
    }
}

/// A server reads whether the datagram came in a 0-RTT packet, which may
/// be replayed (RFC 9001 §9.2), as well.
impl<Tls, Ti> DatagramSide for Server<Tls, Ti>
where
    Server<Tls, Ti>: Side,
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
/// the connection gives them, and what the capability through the shared
/// connection asks of them ([`application::Datagrams`], written once for
/// all queues in [`shared`]).
///
/// `Lc` is this endpoint's reason for closing, which the layer's end
/// carries, and `I` the send strategy types the datagrams' intents are
/// published to. Queues that are lent the strategy's publisher, `publish`,
/// publish through it and keep its key tickets; queues that publish through
/// an intake of their own, asked for when they are built
/// ([`Intake`](Self::Intake)), publish through that instead, and leave the
/// publisher as it is; whoever lent the publisher hands on what changed
/// there either way. A method lent the publisher takes `Ij`, the place of
/// the datagram intents in the sum of intents, and `Kp`, the ticket the
/// publisher gives for them ([`StrategyPublisherForTicket`]); its callers
/// infer both.
///
/// A datagram of the queues is found by its key ([`DatagramKey`]): its
/// intent, the summary of its frame and a holder through the shared
/// connection name it by it, the holder with its credential borrowed
/// ([`HeldDatagram`]). The queues keep a held datagram until its
/// credential comes back ([`withdraw_held`](Self::withdraw_held),
/// [`release_held`](Self::release_held)); an operation that names it after
/// that finds nothing, as a layer whose end is not known.
pub trait DatagramQueues<Lc, I: HostSendStrategyTypes>: Sized {
    /// What the composition configures them with.
    type Config;
    /// What the queues give that can be held apart from them: the
    /// capability of queues that have one, lent the queues from the
    /// established layer's handle, takes it to send apart from the
    /// connection.
    type Handle: Clone;
    /// The handle the queues give the events of the datagrams through: the
    /// connection's
    /// ([`ConnectionEvents::Shared`]).
    type Events;
    /// What the queues leave once their layer ended, for the application
    /// to read after: what it has not read of the datagrams received, how
    /// many were dropped, and what the tickets of the datagrams sent read
    /// ([`DatagramLayerRemains`]). The connection node keeps it for each
    /// layer until the connection ends, and with what the parts keep after
    /// the end ([`DatagramQueuesRemains`]).
    type Remains;
    /// What the queues publish through apart from the publisher they are
    /// lent, got from the strategy's core when they are built
    /// ([`ComponentIntake`]): `()` for queues that publish through the
    /// publisher.
    type Intake;
    /// What the application reads of one datagram received: the side's
    /// ([`DatagramSide::Received`]).
    type Received;

    /// The queues of a layer just built, of the facts `facts`, configured by
    /// `config`, with the handle for the events of the datagrams and what
    /// they publish through apart from the publisher.
    fn new(
        facts: DatagramQueuesFacts,
        config: Self::Config,
        events: Self::Events,
        intake: Self::Intake,
    ) -> Self;

    /// What the queues give that can be held apart from them.
    fn handle(&self) -> Self::Handle;

    /// A DATAGRAM frame arrived in a packet of `level`, no larger than this
    /// side announced. It cannot be refused: what the queues cannot keep
    /// they drop (RFC 9221 §5).
    fn on_datagram_frame(&mut self, level: EncryptionLevel, frame: DatagramFrame<Bytes>);

    /// The established layer ended as `end`: what was received is still
    /// read first, then every read and send reports the end. The datagrams
    /// still waiting are withdrawn as the layer ended, and those whose
    /// packets' fate is not known are lost: nothing settles them after.
    fn layer_ended(&mut self, end: LayerEnd<Lc>);

    /// The driver panicked, and the layer ended as `end`; it is told instead
    /// of [`layer_ended`](Self::layer_ended), which is never called then.
    ///
    /// It only marks the end, where every receive and send and every ticket
    /// of a datagram that waits to be sent looks first, and wakes who waits
    /// to receive and who waits for those tickets to settle. It neither
    /// withdraws the datagrams nor touches the strategy's tickets, as it may
    /// run while the panic unwinds, where a second panic aborts the
    /// process; it takes its locks whatever a holder that panicked left of
    /// them.
    fn driver_panicked(&mut self, end: LayerEnd<Lc>);

    /// What the queues leave, taken once their layer ended: after
    /// [`layer_ended`](Self::layer_ended), or after
    /// [`driver_panicked`](Self::driver_panicked), where it only moves
    /// what is there.
    fn remains(&mut self) -> Self::Remains;

    /// Writes the DATAGRAM frame of the datagram of `key` into `packet`:
    /// its whole payload, without a Length field when the packet has the
    /// last position, otherwise with one of the shortest width. The
    /// datagram counts as sent from then on, the summary of its frame is
    /// its key, and the ticket of its intent goes as written.
    ///
    /// It writes nothing when the datagram was withdrawn, is not there, or
    /// its frame does not fit.
    fn supply_datagram<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        key: DatagramKey,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DatagramSummary, Idx>,
        Q: PacketPosition;

    /// The packet the frame of `summary` was written into was acknowledged:
    /// the datagram's ticket says so, also after it was declared lost.
    fn on_frame_delivered(&mut self, summary: DatagramSummary);

    /// The packet the frame of `summary` was written into was declared
    /// lost, or its send result is unknown, or its link path ended before
    /// it was settled: the datagram's ticket says it was lost; it is not
    /// sent again (RFC 9221 §5.1). A later acknowledgment of it may still
    /// come.
    fn on_frame_lost(&mut self, summary: DatagramSummary);

    /// The intent of the datagram of `key` was not fulfilled for `cause`:
    /// its destination decides now. While the destination degrades, the
    /// datagram is published again to what it gives, with the same ticket
    /// of the application; once it has nothing left, the datagram is
    /// withdrawn ([`DatagramWithdrawCause::DestinationExhausted`]).
    ///
    /// [`DatagramWithdrawCause::DestinationExhausted`]: send::DatagramWithdrawCause::DestinationExhausted
    fn on_intent_unfulfilled<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        key: DatagramKey,
        cause: Unfulfilled,
    ) where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>;

    /// Takes `payload` as one datagram for a holder through the shared
    /// connection, sent with `parameters` to `destination`, and gives back
    /// its key; the queues keep it for its holder until the holder's
    /// credential comes back. When the send queue is full, it refuses the
    /// datagram or withdraws the oldest ones to make room, as it is
    /// configured ([`DatagramOverflow`]).
    ///
    /// # Errors
    ///
    /// [`SendDatagramError`]: the peer takes no DATAGRAM frames, or none
    /// this large, the send queue is full, or the layer ended; nothing is
    /// taken then.
    fn send_held<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        payload: Bytes,
        parameters: &Urgency,
        destination: &AnyActiveLinkPath,
    ) -> Result<DatagramKey, SendDatagramError<Lc>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>;

    /// The next datagram received, in the order they arrived; `Pending`
    /// with the waker of `cx` kept while none is there.
    ///
    /// # Errors
    ///
    /// [`LayerEndedError`] once the layer ended and every datagram it
    /// received was read, or at once once the driver panicked.
    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Received, LayerEndedError<Lc>>>;

    /// What a datagram may hold: what fits any link path in use, and the
    /// peer's limit.
    fn limits(&self) -> DatagramFrameLimits;

    /// How many datagrams received were dropped because the receive queue
    /// was full; it only grows.
    fn dropped_datagrams(&self) -> u64;

    /// Where the datagram of `held` stands now. One that waits is too
    /// large for now when the strategy says so of its ticket, through
    /// `publish` for queues that keep the publisher's tickets; other queues
    /// ask their own tickets. Once its credential came back, withdrawn as
    /// the layer ended.
    fn ticket_state<Kp>(
        &self,
        publish: &StrategyPublisherOf<I>,
        held: HeldDatagram<'_>,
    ) -> DatagramState
    where
        StrategyPublisherOf<I>: PublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = Kp>
            + IntentTicketChanges<Kp>;

    /// The settlement of the datagram of `held`, once there is one;
    /// `Pending` with the waker of `cx` kept while there is none, also
    /// while it waits as too large for now. Once its credential came back,
    /// withdrawn as the layer ended.
    fn poll_ticket_settled(
        &mut self,
        held: HeldDatagram<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramSettlement>;

    /// The holder of `held` gives its credential back and withdraws the
    /// datagram: [`WithdrawReport::Withdrawn`] if it was not written into a
    /// packet, and then it will not be, [`WithdrawReport::Consumed`] if it
    /// was. The queues forget the datagram for its holder.
    fn withdraw_held<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: HeldDatagram<'_>,
    ) -> WithdrawReport
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>;

    /// The holder of `held` gives its credential back without withdrawing
    /// the datagram: it is still sent, and nothing hears whether it is
    /// acknowledged or lost.
    fn release_held(&mut self, held: HeldDatagram<'_>);
}

/// What the queues of one layer leave once it ended
/// (`DatagramLayerRemains`), as the application reads it after: the
/// datagrams received it has not read, how many were dropped, and what the
/// tickets held through the shared connection read, by their datagrams'
/// keys. Nothing of it changes but by these reads: a datagram that waited
/// was withdrawn as the layer ended, and one whose packet's fate was not
/// known was lost.
pub trait DatagramLayerRemains {
    /// What the application reads of one datagram received.
    type Received;

    /// The next datagram received that was not read, in the order they
    /// arrived; `None` once none is left.
    fn pop_received(&mut self) -> Option<Self::Received>;

    /// How many datagrams received were dropped because the receive queue
    /// was full.
    fn dropped(&self) -> u64;

    /// Where the datagram of `key` stands, for its holder through the
    /// shared connection; `None` when the queues left nothing of it.
    fn ticket_state(&self, key: DatagramKey) -> Option<DatagramState>;

    /// How the datagram of `key` was settled; `None` when the queues left
    /// nothing of it.
    fn ticket_settlement(&self, key: DatagramKey) -> Option<DatagramSettlement>;

    /// The holder of the datagram of `key` gives its credential back: what
    /// withdrawing it reports, and it is forgotten; `None` when the queues
    /// left nothing of it.
    fn take_ticket(&mut self, key: DatagramKey) -> Option<WithdrawReport>;
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
    /// [`SendDatagramError::QueueFull`],
    /// a datagram received is dropped.
    #[default]
    RejectNew,
    /// The oldest ones go to make room: a datagram to send is withdrawn,
    /// and its ticket says so; a datagram received is dropped.
    DropOldest,
}

/// The bounds of one queue of datagrams (`DatagramQueueBounds`): how many
/// datagrams and how many bytes of payload it holds at most, and what it
/// does when one more comes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramQueueBounds {
    /// How many datagrams it holds at most.
    pub datagrams: NonZeroUsize,
    /// How many bytes of payload it holds at most.
    pub bytes: usize,
    /// What it does when one more comes.
    pub overflow: DatagramOverflow,
}

/// 64 datagrams, 64 KiB of payload, and the new one refused.
impl Default for DatagramQueueBounds {
    fn default() -> Self {
        Self {
            datagrams: NonZeroUsize::new(64).expect("not zero"),
            bytes: 64 * 1024,
            overflow: DatagramOverflow::default(),
        }
    }
}

/// The largest datagram that fits, as a DATAGRAM frame with a Length field,
/// into a UDP payload of 1200 bytes, the least any link path in use
/// carries (RFC 9000 §14), in any packet version 1 puts the frame in.
///
/// The packet of the most overhead is a 0-RTT packet with Destination and
/// Source Connection IDs of 20 bytes, the longest (RFC 9000 §17.2): its
/// first byte, Version (4), the two lengths and IDs (42), a Length of 2
/// bytes, a packet number of 4 and the AEAD tag of 16 take 69 bytes. A
/// 1-RTT packet takes less, so the bound does not change when the
/// connection leaves 0-RTT, nor with the lengths of the peer's connection
/// IDs, which may differ from one to the next. The frame's type and its
/// Length of 2 bytes leave 1128.
pub(crate) const GUARANTEED_PAYLOAD: usize = 1200 - 69 - 3;

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
        source: codec::ReadDatagramFrameError,
    },
    /// A DATAGRAM frame arrived while the connection has no established
    /// layer and is not closing; the connection closes with INTERNAL_ERROR.
    /// It does not happen, as for version 1's frames of streams.
    #[snafu(display("DATAGRAM frame without an established layer"))]
    NoEstablishedLayer {
        /// Whether the frame had a Length field (type `0x31`).
        has_length: bool,
    },
    /// A server accepted this client's 0-RTT with a `max_datagram_frame_size`
    /// lower than the one the ticket remembers, each 0 when absent
    /// (PROTOCOL_VIOLATION, RFC 9221 §3).
    #[snafu(display(
        "0-RTT accepted with max_datagram_frame_size lowered from {remembered} to {received}"
    ))]
    ZeroRttFrameSizeLowered {
        /// The remembered one.
        remembered: VarInt,
        /// The one of this handshake.
        received: VarInt,
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
            Self::NotAnnounced { .. }
            | Self::FrameTooLarge { .. }
            | Self::ZeroRttFrameSizeLowered { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
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
            Self::ZeroRttFrameSizeLowered { .. } | Self::ParameterValue { .. } => None,
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

/// The driver holds no datagram of its own: every one is published through
/// the intake.
impl<T: crate::clock::ConnectionChoices, L: crate::share::LogicalPathKeys, V>
    crate::frame_source::DriverContentPart<T, L, V, ()> for Part
{
    fn pending<J>(
        _: &crate::take::Lineage<'_, V>,
        _: &crate::share::LinkPathIdentifierOf<T, L>,
        _: &mut crate::send_strategy::DriverContent<J>,
        _: impl Fn(Coprod![DatagramIntent<Urgency>]) -> J,
    ) {
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
/// it, the configuration `C` of the queues, and the policy `R` of the
/// transport parameter on resumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramConnectionArgs<C, R = UseConfiguredParameters> {
    /// The slots of the extension's transport parameter:
    /// `hlist![Some(MaxDatagramFrameSize)]` announces it, `hlist![None]` or
    /// a size of 0 leaves the extension off for the peer.
    pub transport_parameters: PartSlots<Part>,
    /// What the queues of the established layer are configured with.
    pub queues: C,
    /// What decides how the transport parameter goes when a server resumes
    /// a connection; a client does not use it.
    pub resumed_parameters_policy: R,
}

/// The recommended `max_datagram_frame_size`, the default queues and the
/// default policy.
impl<C: Default, R: Default> Default for DatagramConnectionArgs<C, R> {
    fn default() -> Self {
        Self {
            transport_parameters: frunk_core::hlist![Some(MaxDatagramFrameSize::new(
                VarInt::from(RECOMMENDED_MAX_DATAGRAM_FRAME_SIZE)
            ))],
            queues: C::default(),
            resumed_parameters_policy: R::default(),
        }
    }
}

/// The configuration of the queues, `C`, kept in the connection node until
/// the established layer is built.
#[derive(Debug)]
pub struct DatagramQueuesConfig<C>(pub C);

/// It has no deadline and subscribes to nothing; the queues are made from it.
impl<C> PassiveDataComponent for DatagramQueuesConfig<C> {}

/// The connection node keeps the extension's transport parameters as this
/// side sends them, and the configuration of the queues, both from the
/// part's `Args`, and what the queues of each layer that ended leave; so do
/// what the parts keep after the connection's end.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L> LayerShare<T, L, layer::Connection>
    for Part
{
    type Data = HList![
        LocalTransportParameters<PartSlots<Part>>,
        PartResumedParametersPolicy<PartSlots<Part>, DatagramResumedParametersPolicyOf<T>>,
        DatagramQueuesConfig<DatagramQueuesConfigOf<T>>,
        DatagramQueuesRemainsOf<T>
    ];
    type Calls = HNil;
    type Args =
        DatagramConnectionArgs<DatagramQueuesConfigOf<T>, DatagramResumedParametersPolicyOf<T>>;
    type Remains = DatagramQueuesRemainsOf<T>;
}

/// The established layer holds the queues.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L: ConnectionErrorsOf>
    LayerShare<T, L, layer::Established> for Part
where
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
{
    type Data = HList![DatagramQueuesOf<T, L>];
    type Calls = HNil;
}

/// The DATAGRAM frame source finds the queues of the established layer.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L: ConnectionErrorsOf>
    EstablishedSourceComponentsPart<T, L> for Part
where
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
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
    ConnectionArgsOf<T, L>: Selector<
            DatagramConnectionArgs<DatagramQueuesConfigOf<T>, DatagramResumedParametersPolicyOf<T>>,
            I,
        >,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args: &DatagramConnectionArgs<
            DatagramQueuesConfigOf<T>,
            DatagramResumedParametersPolicyOf<T>,
        > = Selector::get(args);
        LocalTransportParameters::Configured(args.transport_parameters)
    }
}

/// The policy on resumption is the one the connection was made with.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L, I>
    Build<T, L, layer::Connection, (Part, I)>
    for PartResumedParametersPolicy<PartSlots<Part>, DatagramResumedParametersPolicyOf<T>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<
            DatagramConnectionArgs<DatagramQueuesConfigOf<T>, DatagramResumedParametersPolicyOf<T>>,
            I,
        >,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args: &DatagramConnectionArgs<
            DatagramQueuesConfigOf<T>,
            DatagramResumedParametersPolicyOf<T>,
        > = Selector::get(args);
        PartResumedParametersPolicy::new(args.resumed_parameters_policy.clone())
    }
}

/// Whether the `max_datagram_frame_size` in `sent` is not lower than the
/// `remembered` one, each 0 when absent: a server that accepts 0-RTT must
/// not lower it (RFC 9221 §3).
fn datagram_limit_kept(remembered: &PartSlots<Part>, sent: &PartSlots<Part>) -> bool {
    sent.head.unwrap_or_default() >= remembered.head.unwrap_or_default()
}

/// The extension holds to its `max_datagram_frame_size`: sending the
/// configured one, it accepts 0-RTT only when that is not lower than the
/// one remembered, each 0 when absent (RFC 9221 §3).
impl<V, I, Ip, Pol> ResumeLocalTransportParametersPart<V, InNode<(I, Ip, Pol)>> for Part
where
    V: GetAt<LocalTransportParameters<PartSlots<Part>>, I>
        + GetAt<PartResumedParametersPolicy<PartSlots<Part>, Pol>, Ip>,
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
            datagram_limit_kept,
        )
    }
}

/// The extension checks its `max_datagram_frame_size` on a client whose
/// 0-RTT the server accepted: the one of this handshake is not lower than
/// the one remembered, each 0 when absent (RFC 9221 §3, MUST).
impl<L, S, J> AcceptedZeroRttParametersPart<L, S, (J,)> for Part
where
    S: Selector<Option<MaxDatagramFrameSize>, J>,
{
    fn check_accepted(remembered: &S, received: &S) -> Result<(), ConnectionError> {
        let size = |slots: &S| {
            Selector::<Option<MaxDatagramFrameSize>, J>::get(slots)
                .map_or(VarInt::ZERO, MaxDatagramFrameSize::get)
        };
        let (remembered, received) = (size(remembered), size(received));
        ensure!(
            received >= remembered,
            ZeroRttFrameSizeLoweredSnafu {
                remembered,
                received
            }
        );
        Ok(())
    }
}

/// The connection keeps the configuration it was made with.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L, I>
    Build<T, L, layer::Connection, (Part, I)> for DatagramQueuesConfig<DatagramQueuesConfigOf<T>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<
            DatagramConnectionArgs<DatagramQueuesConfigOf<T>, DatagramResumedParametersPolicyOf<T>>,
            I,
        >,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args: &DatagramConnectionArgs<
            DatagramQueuesConfigOf<T>,
            DatagramResumedParametersPolicyOf<T>,
        > = Selector::get(args);
        DatagramQueuesConfig(args.queues.clone())
    }
}

/// What the queues of the layers that ended leave (`DatagramQueuesRemains`),
/// by layer: `X` is what one layer's leave ([`DatagramQueues::Remains`]).
/// The connection node keeps it from the first layer's end on, and it is
/// the part's share of what the parts keep after the connection's end.
pub struct DatagramQueuesRemains<X> {
    layers: Vec<(LayerId, X)>,
}

impl<X> Default for DatagramQueuesRemains<X> {
    fn default() -> Self {
        Self { layers: Vec::new() }
    }
}

impl<X> fmt::Debug for DatagramQueuesRemains<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramQueuesRemains")
            .field("layers", &self.layers.len())
            .finish_non_exhaustive()
    }
}

impl<X> DatagramQueuesRemains<X> {
    /// Keep what the queues of the layer `id` left.
    fn keep(&mut self, id: LayerId, remains: X) {
        self.layers.push((id, remains));
    }

    /// What the queues of the layer `id` left, if it ended.
    pub(crate) fn layer_mut(&mut self, id: LayerId) -> Option<&mut X> {
        self.layers
            .iter_mut()
            .find_map(|(kept, remains)| (*kept == id).then_some(remains))
    }
}

/// It starts empty.
impl<T: Choices<Side: DatagramSide, Host: DatagramChoices>, L>
    Build<T, L, layer::Connection, (Part, ())> for DatagramQueuesRemainsOf<T>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Self::default()
    }
}

/// It has no deadline and subscribes to nothing: the queues' end actions
/// add to it. Once the connection ended, it goes into what the parts keep.
impl<T, L, I, Ir> DataComponent<T, L, layer::Connection, (Part, I, Ir)>
    for DatagramQueuesRemainsOf<T>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T>,
    RemainsOf<T, L>: Selector<Self, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<Self, I>,
{
    fn remains<'v>(
        lineage: &mut LineageOf<'v, T, L, layer::Connection>,
        out: &mut RemainsOf<T, L>,
    ) {
        let kept = core::mem::take(&mut *lineage.get_mut::<Self, I>());
        *Selector::<Self, Ir>::get_mut(out) = kept;
    }
}

/// Keep what the queues `queues` of the layer that ends left in the
/// connection node, `Ih` being where the connection handle's state is in
/// `lineage` and `Ik` where the record is.
fn keep_remains<T, L, X, Ih, Ik, V>(lineage: &mut crate::take::Lineage<'_, V>, queues: &mut X)
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    SendTypes<T, L>: HostSendStrategyTypes,
    X: DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>, Remains = DatagramLayerRemainsOf<T>>,
    V: GetAt<ConnectionHandleStateOf<T, L>, Ih> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    let Some(id) = lineage
        .get::<ConnectionHandleStateOf<T, L>, Ih>()
        .latest_layer()
    else {
        // invariant: the state hears of every layer as it is built
        debug_assert!(false, "an established layer ends that was not built");
        return;
    };
    let remains = queues.remains();
    lineage
        .get_mut::<DatagramQueuesRemainsOf<T>, Ik>()
        .keep(id, remains);
}

/// Where the queues are among the established layer's components.
#[derive(Debug)]
pub struct ChosenDatagramQueues;

/// The queues are made when the established layer is built, from the
/// peer's `max_datagram_frame_size` as received and the configuration the
/// connection node keeps; a layer built before the peer's parameters are
/// known takes the peer's as absent: nothing is sent. The queues ask the
/// core of the send strategy for what they publish through apart from the
/// publisher ([`ComponentIntake`]), `Ij` being the place of the datagram
/// intents in the sum of intents.
///
/// When the layer ends, the queues hear that the connection closed, for the
/// reason in the record of why the connection closed; what they leave
/// then goes into the connection node, under the layer's identity, which
/// the connection handle's state gives.
impl<T, L, X, Ip, Ic, Ir, Iev, Ih, Ik, Isc, Jm, Ij>
    Build<
        T,
        L,
        layer::Established,
        (ChosenDatagramQueues, (Ip, Ic, Ir, Iev, Ih, Ik, Isc), (Jm, Ij)),
    > for X
where
    T: Choices<
        Side: DatagramSide,
        Host: DatagramChoices<
            DatagramQueues: DatagramQueuesFamily<
                Queues<
                    CloseCauseOf<T, L>,
                    SendTypes<T, L>,
                    <T as crate::v1::MakerChoices>::Side,
                    SharedEventsOf<T, L>,
                > = X,
            >,
        >,
    >,
    L: LineagePartList<T> + ConnectionErrorsOf + ParametersOf<TransportParameterSpace>,
    SendTypes<T, L>: ComponentIntake<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>, Ij>,
    X: DatagramQueues<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            Config = DatagramQueuesConfigOf<T>,
            Events = SharedEventsOf<T, L>,
            Remains = DatagramLayerRemainsOf<T>,
            Intake = <SendTypes<T, L> as ComponentPublishing<
                DatagramQueuesFamilyOf<T>,
                DatagramIntent<Urgency>,
            >>::Intake,
        >,
    TransportParameterSlots<L>: Selector<Option<MaxDatagramFrameSize>, Jm>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>
        + GetAt<DatagramQueuesConfig<DatagramQueuesConfigOf<T>>, Ic>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>
        + GetAt<ConnectionHandleStateOf<T, L>, Ih>
        + GetAt<DatagramQueuesRemainsOf<T>, Ik>
        + GetAt<SendStrategyCore<SendStrategyOf<T, L>>, Isc>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::Established>,
        _: &mut ArgsOf<T, L, layer::Established>,
    ) -> Self {
        // a client's early layer runs on the remembered parameters, as
        // 0-RTT keeps to them (RFC 9221 §3)
        let peer = parents
            .get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>()
            .slots()
            .and_then(|slots| *Selector::<Option<MaxDatagramFrameSize>, Jm>::get(slots))
            .unwrap_or_default();
        let config = parents
            .get::<DatagramQueuesConfig<DatagramQueuesConfigOf<T>>, Ic>()
            .0
            .clone();
        let events = parents
            .get::<ConnectionEventSink<EventsOf<T, L>>, Iev>()
            .events()
            .shared();
        let intake = {
            let mut core = parents.get_mut::<SendStrategyCore<SendStrategyOf<T, L>>, Isc>();
            match core.strategy_mut() {
                Some(strategy) => <SendTypes<T, L> as ComponentIntake<
                    DatagramQueuesFamilyOf<T>,
                    DatagramIntent<Urgency>,
                    Ij,
                >>::intake(strategy),
                // every link path drained, so nothing the queues publish is
                // sent: a core of their own gives what they ask for
                None => <SendTypes<T, L> as ComponentIntake<
                    DatagramQueuesFamilyOf<T>,
                    DatagramIntent<Urgency>,
                    Ij,
                >>::intake(&mut SendStrategyOf::<T, L>::default()),
            }
        };
        X::new(DatagramQueuesFacts { peer }, config, events, intake)
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
        keep_remains::<T, L, X, Ih, Ik, _>(parents, &mut self);
    }
}

/// The queues have no deadline and read nothing: the dispatch of frames and
/// the application change them. When the driver panicked, they are told
/// the layer's end ([`DatagramQueues::driver_panicked`]), for the reason in
/// the record of why the connection closed, which the dropped future wrote,
/// and what they leave goes into the connection node, as at the layer's
/// end.
impl<T, L, X, Iq, Ir, Ih, Ik>
    DataComponent<T, L, layer::Established, (ChosenDatagramQueues, Iq, Ir, Ih, Ik)> for X
where
    T: Choices<
        Side: DatagramSide,
        Host: DatagramChoices<
            DatagramQueues: DatagramQueuesFamily<
                Queues<
                    CloseCauseOf<T, L>,
                    SendTypes<T, L>,
                    <T as crate::v1::MakerChoices>::Side,
                    SharedEventsOf<T, L>,
                > = X,
            >,
        >,
    >,
    L: LineagePartList<T> + ConnectionErrorsOf,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    X: DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>, Remains = DatagramLayerRemainsOf<T>>,
    for<'v> <L as LineageLists<'v, T>>::Established: GetAt<X, Iq>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<ConnectionHandleStateOf<T, L>, Ih>
        + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
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
        let remains = {
            let mut queues = lineage.get_mut::<X, Iq>();
            queues.driver_panicked(LayerEnd::ConnectionClosed(reason));
            queues.remains()
        };
        let Some(id) = lineage
            .get::<ConnectionHandleStateOf<T, L>, Ih>()
            .latest_layer()
        else {
            // invariant: as at the layer's end
            debug_assert!(false, "an established layer was not built");
            return;
        };
        lineage
            .get_mut::<DatagramQueuesRemainsOf<T>, Ik>()
            .keep(id, remains);
    }
}

// ---- the frames received ----

/// The extension reads its frames as the wire format's part.
impl FrameSetPart for Part {
    type Run<D> = DatagramFrame<D>;
    type Kind = FrameType;
    type TypeValue = DatagramTypeValue;
    type FieldsError = codec::ReadDatagramFrameError;

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

    fn read_run<S: Buf + SplitTo>(
        source: &mut S,
        type_value: DatagramTypeValue,
    ) -> Result<DatagramFrame<S>, codec::ReadDatagramFrameError> {
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
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    DatagramQueuesOf<T, L>: DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>> + 'static,
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
        let Some(hlist_pat![mut queues]) =
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

    fn fields_error(error: codec::ReadDatagramFrameError) -> ConnectionError {
        ConnectionError::ReadFrameFields { source: error }
    }
}

#[cfg(test)]
mod tests;
