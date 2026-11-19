//! QUIC version 1 in a connection: the part, what it chooses, and its
//! components.
//!
//! [`Part`] is version 1 as one part of a composition. Its shares put the
//! keys of each encryption level, the counts of the AEAD's usage
//! ([`aead_usage`]), the CRYPTO data received and sent at each level
//! ([`crypto`]) with the intents of what is to be sent, what only the
//! connection's side has ([`handshake_done`]) and the NEW_TOKEN frames a
//! server sends ([`new_token`]), the transport parameters,
//! the idle timeout and what the connection was made with for its first
//! logical link and from its first flight
//! ([`first_flight`]) in the connection node, with the
//! recovery factory, the record of why the connection closed
//! ([`close`]) and the cell of the application's request to close
//! ([`close_request`]), which at the start of every poll takes the request
//! into the record, and the state the application's connection handle
//! reads, which follows the record, the handshake and the established
//! layer ([`application_handles`]); the connection's one call, the advancing call, runs the
//! handshake and keeps its exporter ([`advancing`]); the clone of the
//! link, the facts about it and the anti-amplification limit in the entry of
//! each logical link, whose call follows the link's datagram size limit
//! ([`link_ceiling`]); the role in each link path; and in each link path's
//! recovery layer, what the factory makes for it with the state beside them
//! and its ECN state ([`ecn`]),
//! its loss detection state for each packet number space and its probe
//! timeout; the established layer holds the streams ([`streams`]). Each
//! logical path keeps, for each packet number space, its
//! packet number state, its receive journals, its ACK obligation and its
//! send journals, which keep the feedback summaries of the frames sent
//! ([`feedback`]); the packet numbers the current 1-RTT key generation
//! has seen ([`key_phase`]); and what it receives ([`input`]): its datagram receiver, the first one taken
//! from what the connection was made with, and the inputs it holds until
//! their keys come; its receiving call takes each datagram in, and the ACK
//! frames it carries settle what was sent ([`ack`]). A link path's sending
//! call ([`sending`]) writes its datagrams into a batch ([`datagram_batch`]),
//! one packet after the other ([`packet_writer`]), with the frames of
//! version 1 ([`frames`]), as its send planner plans them, and hands the
//! batch to the link. Once
//! a reason for closing is written, the link paths close, each sealing its
//! close packet ([`close_packet`]) with the connection's close policy, and
//! their recovery layers and the established layer end; the keys keep only
//! their receiving half, and the connection ends with its last link path.
//! A link path that ends hands back what it had not settled as lost. Each
//! logical path follows the peer's connection migration with its
//! migration policy ([`migration`]): what packets from a new logical link
//! make, and which link path is active; a client's second call of the
//! logical path migrates it to its server's preferred address
//! ([`preferred_address`]), on a link its connector takes
//! ([`link_connector`]).

pub mod ack;
pub mod address_token;
pub mod advancing;
pub mod aead_usage;
pub mod amplification;
pub mod application_handles;
pub mod close;
pub mod close_packet;
pub mod close_request;
pub mod component_events;
pub mod confirmation;
pub mod connection_ids;
pub mod crypto;
pub mod datagram_batch;
pub mod dispatch;
pub mod ecn;
pub mod error;
pub mod events;
pub mod feedback;
pub mod first_flight;
pub mod frames;
pub mod handshake_done;
pub mod idle;
pub mod input;
pub mod key_phase;
pub mod key_update;
pub mod keys;
pub mod link;
pub mod link_ceiling;
pub mod link_connector;
pub mod link_end;
pub mod long_header_claim;
pub mod loss_detection;
pub mod migration;
pub mod new_token;
pub mod packet_writer;
pub mod parameters;
pub mod path_response;
pub mod path_validation;
pub mod pmtu_probe;
pub mod preferred_address;
pub mod pto;
pub mod receive;
pub mod recovery;
pub mod retry;
pub mod send;
pub mod send_planning;
pub mod sending;
pub mod space_retirement;
pub mod spaces;
pub mod stateless_reset;
pub mod streams;
pub mod version_negotiation;

#[cfg(test)]
mod tests;

use core::{fmt::Debug, marker::PhantomData, num::NonZeroUsize, time::Duration};

use nitori_tls::schedule::TrafficSecret;
use sakuya_packet_protection::{
    backend::CryptoBackend,
    initial::{INITIAL_AEAD, InitialSecrets},
};
use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::{ParametersOf, ParametersPart, codec::ReadParametersError},
    parts::{Coproduct, HList, HNil, PartsError, Selector},
    v1::packet_number::PacketNumber,
    v1::role::Role,
    v1::transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, TransportParameterValueErrors,
        integer::{MaxAckDelay, MaxIdleTimeout},
    },
    var_int::VarInt,
};

use self::component_events::{
    ClosePacketChanged, CloseReasonWritten, HandshakeConfirmed, KeyPhaseChanged, KeysDiscarded,
    KeysRetiring, LinkPathRoleChanged, LocalTransportParametersSent, PeerTransportParametersKnown,
    RttSampled, level,
};
use self::feedback::LineageFeedback;
use crate::{
    call::CallBundle,
    clock::{CheckedAdd, ConnectionChoices, InstantOf, LinkIdOf},
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, RequestOf,
    },
    component_event::{EventSubscriptions, Happened, NodeEnding, NodeStarted, TriggeredEvents},
    error::{
        ConnectionErrorOf, ConnectionErrorPart, ConnectionErrorsOf,
        TransportParameterValueErrorPart,
    },
    feedback::FeedbackSummariesOf,
    frame_source::{
        EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts,
        EstablishedSourceComponentsPart, FrameSource,
    },
    layer::{self, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    send_strategy::{AnyActiveLinkPath, SendStrategyTypes},
    share::{
        ConnectionArgsOf, FlatMut, LayerShare, LineageLists, LineagePartList, LogicalPathKeyShare,
        LogicalPathKeys, NodeData,
    },
    take::{GetAt, ReadEach, TakeEach},
};

use std::sync::Arc;

use self::path_response::PendingPathResponse;
use self::pmtu_probe::PendingPmtuProbe;
use self::{
    address_token::AddressTokenSink,
    advancing::{ClientAdvancingKind, ConnectionExporter, HandshakeStart, ServerAdvancingKind},
    aead_usage::{AeadUsage, KeyUpdateThreshold},
    amplification::{AddressValidation, AntiAmplification, AntiAmplificationFactor},
    application_handles::connection::{
        ClientHandshakeFacts, ConnectionHandleRemainsOf, ConnectionHandleStateOf,
        ServerHandshakeFacts,
    },
    close::{ApplicationClose, CloseReasonRecord, LocalCloseCause},
    close_packet::{ClosePacket, ConnectionImmediateClosePolicy},
    close_request::CloseRequestCell,
    confirmation::HandshakeConfirmation,
    connection_ids::{
        ConnectionIdsOf, ConnectionResetTokenRegistry, DestinationConnectionIdConfig,
        DestinationConnectionIdConfigOf, FirstLocalConnectionId, InitialDestinationConnectionIds,
        LinkPathResetTokenRegistrar, LocalConnectionIdIssuer, LocalConnectionIdRegistrationOf,
        PeerHandshakeConnectionId, PeerOf, ResetTokenRegistrarOf,
    },
    crypto::{
        CryptoReceiveBuffer, CryptoReceiveCapacities, CryptoReceiver,
        send::{CryptoSendBuffer, CryptoSender},
    },
    ecn::LinkPathEcnState,
    feedback::HandshakeDoneSummary,
    first_flight::{FirstFlight, FirstFlightStart},
    handshake_done::{ClientOnlyStart, ClientOnlyState, HandshakeDoneSource},
    idle::IdleTimeout,
    input::{
        InitialPathReceiver, LogicalPathDatagramReceiver, LogicalPathInput,
        LogicalPathReceivingKind, LogicalPathReceivingLimits,
    },
    key_phase::KeyPhaseNumbers,
    keys::{
        DirectionKeys, HandshakeKeys, InitialKeys, LevelKeys, OneRttKeys, PacketProtectionBackend,
        ZeroRttReceiveKeys, ZeroRttReceiving, ZeroRttSending,
    },
    link::{FirstLinkStart, LinkClone, LinkFacts},
    link_ceiling::LinkCeilingWatchingKind,
    link_end::LinkEndWatchingKind,
    loss_detection::LossDetectionOf,
    new_token::{NewTokenIntent, NewTokenSource, NewTokenSummary, NoNewTokens, ServerOnlyStart},
    parameters::{
        LocalTransportParameters, PartResumedParametersPolicy, PeerTransportParameters,
        ResumedParametersPolicy, UseConfiguredParameters,
    },
    pto::ProbeTimeout,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, OthersOf, PmtuOf, RecoveryConfigOf,
        RecoveryFactoryOf, RttOf,
    },
    retry::{ClientRetryPolicy, ReceivedRetry, RetryDecision},
    send::{PendingProbePings, SendTypes},
    send_planning::{
        HostSendStrategyTypes, IntakeOf, LinkPathPlannerOf, SendStrategyCore, SendStrategyIntake,
        SendStrategyOf,
    },
    sending::{DatagramAcceptance, LinkPathSendingKind, LinkPathSendingLimits},
    space_retirement::PacketNumberSpaceRetirement,
    spaces::{AckObligationsOf, DEFAULT_MAX_ACK_DELAY, SendJournalsOf, peer_max_ack_delay},
    stateless_reset::StatelessResetSignal,
    streams::{
        StreamSetConfig, StreamSetFamily, StreamsOf,
        resets::{StreamResets, StreamResetsOf, StreamResetsPart},
    },
};
use crate::connection_id::{
    DestinationConnectionIdStrategy,
    local::{LocalConnectionIdStrategy, NewConnectionIdSummary},
    reset_token::ResetTokenRegistry,
};
use crate::role::LinkPathRole;
use bytes::Bytes;
use nitori_tls::{
    alert::CallsForAlert,
    client::engine::ClientHandshakeSteps,
    engine::{CryptoLevel, HandshakeError},
    extension::alpn::ProtocolName,
    schedule::Exporter,
    server::{engine::ServerHandshakeSteps, targets::SelectedTarget},
};
use sakuya_link::{EcnMarking, Link};
use sakuya_recovery::{
    ack_obligation::AckObligation,
    factory::{LendCongestion, RecoveryFactory},
    loss::LossThresholds,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pto::probe_timeout,
    receive_journals::{MaxAckRanges, ReceiveJournals},
    rtt::RttEstimator,
    send_journals::{SendJournals, SentPacketState},
};
use sakuya_stream::connection::{AbortCause, CloseReason};

/// QUIC version 1, one part of a composition.
#[derive(Debug)]
pub struct Part;

/// Version 1 has one logical path and adds nothing to its key.
impl LogicalPathKeyShare for Part {
    type Fields = HNil;
}

/// The transport parameters of version 1 are those its wire format defines
/// (RFC 9000 §18.2): the slots of a composition's parameters are found
/// from its list of parts.
impl ParametersPart<TransportParameterSpace> for Part {
    type Parameters =
        <sakuya_wire::v1::Part as ParametersPart<TransportParameterSpace>>::Parameters;
}

/// Version 1 finds its own [`ConnectionError`](error::ConnectionError),
/// whose failures of RESET_STREAM frames are those of how the composition
/// resets streams.
impl<L: StreamResetsOf> ConnectionErrorPart<L> for Part {
    type ConnectionError = error::V1ConnectionErrorOf<L>;
}

/// Version 1 passes the reset kind on: it starts as RFC 9000's.
impl StreamResetsPart for Part {
    type Fold<Prev: StreamResets> = Prev;
}

/// A value of a transport parameter of version 1 that breaks a rule of its
/// type is a failure of reading the peer's transport parameters, as any
/// other failure of their encoding is.
///
/// The impl is written for any sum that is not `CNil`, so that it stays
/// apart from the impl every part has for `CNil`; only the sum of the
/// failures of version 1's own types meets its bound.
impl<H, T, L: StreamResetsOf> TransportParameterValueErrorPart<Coproduct<H, T>, L> for Part
where
    PartsError<Coproduct<H, T>>: Into<PartsError<TransportParameterValueErrors>>,
{
    fn value_error(
        id: VarInt,
        source: PartsError<Coproduct<H, T>>,
    ) -> error::V1ConnectionErrorOf<L> {
        error::ConnectionError::ReadTransportParameters {
            source: ReadParametersError::InvalidValue {
                id,
                source: source.into(),
            },
        }
    }
}

/// What the maker of a connection of version 1 fixes: the endpoint, or a
/// test. The maker's type is the connection's choices ([`Choices`]); the
/// host picks the rest ([`HostChoices`]).
pub trait MakerChoices: ConnectionChoices {
    /// The cryptographic backend that derives the packet protection keys;
    /// the connection keeps a clone for the levels after Initial.
    type Crypto: CryptoBackend + Clone + 'static;
    /// Which side of the connection this side is.
    type Side: Side;
    /// The datagram receiver of a logical path.
    type Receiver: LogicalPathDatagramReceiver<Self::Link> + 'static;
    /// What the connection holds to register the reset tokens of the
    /// peer's connection IDs for detection: it makes the registrar of each
    /// link path, for its link's peer and its logical path's
    /// [`StatelessResetSignal`].
    type ResetTokenRegistry: ResetTokenRegistry<PeerOf<Self>, Arc<StatelessResetSignal>, Registrar: 'static>
        + Clone
        + 'static;
    /// What issues this side's connection IDs after the first, one for each
    /// connection: it generates each with its stateless reset token and
    /// registers it with routing before it is disclosed.
    type ConnectionIdIssuer: crate::connection_id::local::ConnectionIdIssuer<Registration: 'static>
        + 'static;
}

/// What a composition chooses for version 1: what its maker fixes, and the
/// host's choices ([`Host`](Self::Host)), read through the aliases
/// [`AckObligationOf`] and the others.
///
/// The host's choices take only [`MakerChoices`]: were they to take
/// `Choices`, a maker's type would be choices once the host's type is its
/// host's choices, and the host's type that once the maker's type is
/// choices.
pub trait Choices: MakerChoices {
    /// The host's type, which picks the rest.
    type Host: HostChoices<Self>;
}

/// What the host picks for the connections of version 1 that the maker `T`
/// makes. What has one implementation in sakuya has it as its default.
pub trait HostChoices<T: MakerChoices + ?Sized>: 'static {
    /// The application's own error type for closing the connection.
    type ApplicationError: ApplicationClose + 'static;
    /// What stores the CRYPTO data of one encryption level until the
    /// handshake engine reads it.
    type CryptoReceiveBuffer: CryptoReceiveBuffer + Default + 'static =
        crypto::FragmentedCryptoReceiveBuffer;
    /// What keeps the CRYPTO data of one encryption level that this side
    /// sends, until the peer acknowledges it.
    type CryptoSendBuffer: CryptoSendBuffer + Default + Unpin + 'static =
        crypto::send::OffsetMapCryptoSendBuffer;
    /// What makes the RTT estimate, the stored part of congestion control
    /// and the datagram size probing policy of each link path, one for each
    /// connection. `V` identifies a link path, as found from the list of
    /// parts: the logical link when the connection supports version 1
    /// alone. The default's congestion controller is CUBIC; a host that
    /// wants NewReno picks
    /// [`NewRenoRecoveryFactory`](sakuya_recovery::factory::NewRenoRecoveryFactory).
    type Recovery<V: Clone + Eq + Debug + 'static>: RecoveryFactory<T::Link, Via = V> + 'static =
        sakuya_recovery::factory::CubicRecoveryFactory<V>;
    /// What decides when an ACK frame is due, one for each packet number
    /// space of a logical path.
    type AckObligation: AckObligation<InstantOf<T>> + 'static =
        sakuya_recovery::ack_obligation::Rfc9000AckObligation<InstantOf<T>>;
    /// What records the packets sent in one packet number space of a
    /// logical path, one for each space; it starts empty. `S` is the
    /// summary of a frame, as found from the list of parts, and `P`
    /// identifies a link path, as the recovery factory's `V`.
    type SendJournals<S: 'static, P: Clone + Eq + Debug + 'static>: SendJournals<S, InstantOf<T>, P>
        + Default
        + 'static = sakuya_recovery::send_journals::DequeSendJournals<InstantOf<T>, S, P>;
    /// What adjusts the close this endpoint sends at each encryption level:
    /// an [`ImmediateClosePolicy`](close::ImmediateClosePolicy) of this
    /// endpoint's reason for closing, [`CloseCauseOf`] for the composition's
    /// list of parts. The connection keeps the one it was made with.
    type ImmediateClosePolicy: Clone + 'static = close::PassThroughImmediateClosePolicy;
    /// What decides, for a connection a server resumes, how version 1's
    /// transport parameters go: reject 0-RTT, send those remembered, or
    /// send those configured ([`ResumedParametersPolicy`]). The connection
    /// keeps the one it was made with; the default sends those configured.
    type ResumedParametersPolicy: ResumedParametersPolicy<TransportParameterSlots> + Clone + 'static =
        UseConfiguredParameters;
    /// The core of the send strategy, for the types `I` the composition
    /// gives it; it starts as its default makes it.
    type SendStrategy<I: SendStrategyTypes>: Default =
        crate::send_strategy::ranked::RankedSendStrategy<I>;
    /// What decides which of the peer's connection IDs this side sends
    /// with, one for each logical path; it registers reset tokens through
    /// the registrars of the maker's
    /// [`ResetTokenRegistry`](MakerChoices::ResetTokenRegistry), and writes
    /// the RETIRE_CONNECTION_ID frames that retire the peer's connection
    /// IDs.
    type DestinationConnectionIds: DestinationConnectionIdStrategy<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>
        + for<'a> FrameSource<Item<'a> = u64, Summary = send::RetireConnectionIdSummary>
        + 'static = crate::connection_id::sequence_map::SequenceMapDestinationConnectionIdStrategy<
        LinkIdOf<T>,
        ResetTokenRegistrarOf<T>,
    >;
    /// What decides how many of this side's connection IDs the peer holds
    /// and when they are issued and dropped, one for each logical path; it
    /// issues them with the maker's
    /// [`ConnectionIdIssuer`](MakerChoices::ConnectionIdIssuer), keeps
    /// their registrations, and writes the NEW_CONNECTION_ID frames that
    /// disclose them.
    type LocalConnectionIds: LocalConnectionIdStrategy<LinkIdOf<T>, InstantOf<T>, LocalConnectionIdRegistrationOf<T>>
        + for<'a> FrameSource<Item<'a> = u64, Summary = NewConnectionIdSummary>
        + 'static = crate::connection_id::local::SequenceMapLocalConnectionIdStrategy<
        LocalConnectionIdRegistrationOf<T>,
        InstantOf<T>,
    >;
    /// The kind of the connection's stream set in the established layer
    /// ([`streams`]), which gives the set's configuration and the
    /// parameters application data is sent with; the send strategy
    /// constrains the parameters with a trait of its own.
    type Streams: StreamSetFamily = streams::locked::LockedStreamSetFamily;
    /// What decides the choices of connection migration that RFC 9000
    /// leaves to the endpoint, one for each logical path: which packets from
    /// a new logical link build a link path, when the active link path
    /// switches and with which recovery layer, the timing of path
    /// validation and how long a link path settles
    /// ([`MigrationPolicy`](migration::MigrationPolicy), asked where version
    /// 1 uses it). The default needs the peer's ends to state their network
    /// address ([`PeerAddress`](sakuya_link::PeerAddress)).
    type MigrationPolicy: Default + 'static = migration::Rfc9000MigrationPolicy;
    /// What receives the connection's events ([`events`]), one for each
    /// connection, kept in the connection node; `L` is the composition's
    /// list of parts. The events that carry packets need
    /// [`PacketEvents`](events::PacketEvents) for that list besides, which
    /// the composition proves; the default records nothing, for any list.
    type Events<L>: events::ConnectionEvents<InstantOf<T>> = events::NoEvents;
}

/// The host's choices of the choices `T`.
pub type HostOf<T> = <T as Choices>::Host;
/// The application's error type of the choices `T`.
pub type ApplicationErrorOf<T> = <HostOf<T> as HostChoices<T>>::ApplicationError;
/// The CRYPTO receive buffer of the choices `T`.
pub type CryptoReceiveBufferOf<T> = <HostOf<T> as HostChoices<T>>::CryptoReceiveBuffer;
/// The CRYPTO send buffer of the choices `T`.
pub type CryptoSendBufferOf<T> = <HostOf<T> as HostChoices<T>>::CryptoSendBuffer;
/// The ACK obligation of the choices `T`.
pub type AckObligationOf<T> = <HostOf<T> as HostChoices<T>>::AckObligation;
/// The close policy of the choices `T`.
pub type ImmediateClosePolicyOf<T> = <HostOf<T> as HostChoices<T>>::ImmediateClosePolicy;
/// The policy of version 1's transport parameters on resumption, of the
/// choices `T`.
pub type ResumedParametersPolicyOf<T> = <HostOf<T> as HostChoices<T>>::ResumedParametersPolicy;
/// The destination connection ID strategy of the choices `T`.
pub type DestinationConnectionIdsOf<T> = <HostOf<T> as HostChoices<T>>::DestinationConnectionIds;
/// The local connection ID strategy of the choices `T`.
pub type LocalConnectionIdsOf<T> = <HostOf<T> as HostChoices<T>>::LocalConnectionIds;
/// The migration policy of the choices `T`.
pub type MigrationPolicyOf<T> = <HostOf<T> as HostChoices<T>>::MigrationPolicy;
/// The kind of stream set of the choices `T`.
pub type StreamSetFamilyOf<T> = <HostOf<T> as HostChoices<T>>::Streams;
/// The parameters application data is sent with, of the choices `T`.
pub type SendParametersOf<T> = <StreamSetFamilyOf<T> as StreamSetFamily>::SendParameters;
/// The configuration of the stream set of the choices `T`.
pub type StreamSetConfigOf<T> = <StreamSetFamilyOf<T> as StreamSetFamily>::Config;
/// The receiver of the connection's events, of the choices `T` and the list
/// of parts `L`.
pub type EventsOf<T, L> = <HostOf<T> as HostChoices<T>>::Events<L>;
/// What the receiver of the connection's events is made from, of the
/// choices `T` and the list of parts `L`.
pub type EventsConfigOf<T, L> = <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::Config;

/// The handle the application's threads give the connection's events
/// through, of the choices `T` and the list of parts `L`.
pub type SharedEventsOf<T, L> = <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::Shared;

/// The 0-RTT keys of the side of the choices `T`
/// ([`Side::OwnZeroRttKeys`]).
pub(crate) type OwnZeroRttKeysOf<T> =
    <<T as MakerChoices>::Side as Side>::OwnZeroRttKeys<<T as MakerChoices>::Crypto, InstantOf<T>>;

/// This endpoint's reason for closing a connection of the choices `T` and
/// the list of parts `L`: the connection's error, the handshake's error,
/// which holds the alert failure of the side's handshake engine, the
/// application's error, or why the choices' link ended.
pub type CloseCauseOf<T, L> = LocalCloseCause<
    ConnectionErrorOf<L>,
    HandshakeError<
        <<T as crate::v1::MakerChoices>::Side as Side>::AlertError,
        ConnectionErrorOf<L>,
    >,
    ApplicationErrorOf<T>,
    <<T as ConnectionChoices>::Link as Link>::RecvError,
>;

/// What differs between the two sides of a connection: the handshake
/// engine and the call that advances it, the data only this side has, and
/// one method for each difference in behavior.
pub trait Side: 'static {
    /// The role of this side.
    const ROLE: Role;

    /// The start state of this side's handshake engine.
    type Tls;

    /// The kind of this side's advancing call, the one call of the
    /// connection node, which runs the handshake
    /// ([`advancing`]).
    type Advancing;

    /// The exporter this side's handshake gives when it completes, which
    /// the connection node keeps until the connection closes.
    type Exporter: 'static;

    /// What this side knows of its handshake once it completed, which the
    /// connection handle gives
    /// ([`ClientHandshakeFacts`], [`ServerHandshakeFacts`]).
    type HandshakeFacts: 'static;

    /// What an established layer of this side runs with of the handshake's
    /// selection, which the layer's handle gives: the application protocol,
    /// on a server together with the selected target.
    type LayerSelection: application_handles::established_layer::LayerSelection + 'static;

    /// How this side's handshake engine fails with an alert: the failure
    /// that [`HandshakeError`] holds for it.
    type AlertError: CallsForAlert + 'static;

    /// What only this side's connection starts with, besides its handshake
    /// engine, which [`ConnectionArgs::side`] gives: for a server, what its
    /// [`NewTokens`](Side::NewTokens) data is made from
    /// ([`ServerOnlyStart`]); for a client, what its [`Own`](Side::Own)
    /// data is made from ([`ClientOnlyStart`]).
    type Start;

    /// The data component in the connection node that only this side has.
    ///
    /// The HANDSHAKE_DONE frames of version 1 are found in it: a server's
    /// sends them; a client's never has one waiting and writes nothing (RFC
    /// 9000 §19.20).
    type Own: for<'a> FrameSource<Item<'a> = (), Summary = HandshakeDoneSummary> + 'static;

    /// The data component in the connection node where the NEW_TOKEN
    /// frames of version 1 are found ([`new_token`]): a server's issues and
    /// sends them ([`NewTokenSource`]); a client's never has one waiting
    /// and writes nothing ([`NoNewTokens`]), as a client must not send the
    /// frame (RFC 9000 §19.7).
    type NewTokens: for<'a> FrameSource<Item<'a> = (), Summary = NewTokenSummary> + 'static;

    /// The 0-RTT keys only this side has, a data component of the
    /// connection node: a server's to read 0-RTT packets
    /// ([`ZeroRttReceiving`]), a client's to send them ([`ZeroRttSending`]).
    type OwnZeroRttKeys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>: 'static;

    /// The keys to read a 0-RTT packet with, as `keys` keeps them.
    ///
    /// A server's are not decided before its ServerHello is written, then
    /// are there while it reads 0-RTT. A client never has any: it drops
    /// every 0-RTT packet (RFC 9001 §5.6).
    fn zero_rtt_receive_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &Self::OwnZeroRttKeys<B, I>,
    ) -> ZeroRttReceiveKeys<'_, B>;

    /// The keys to send a 0-RTT packet with, as `keys` keeps them.
    ///
    /// A server never has any: only a client sends 0-RTT (RFC 9001 §4.6.1).
    fn zero_rtt_send_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &Self::OwnZeroRttKeys<B, I>,
    ) -> Option<&DirectionKeys<B>>;

    /// Whether `keys` start to retire with the next 1-RTT packet this side
    /// processes: a server's while it reads 0-RTT and they do not retire
    /// yet (RFC 9001 §4.9.3); never a client's.
    fn zero_rtt_awaits_retirement<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &Self::OwnZeroRttKeys<B, I>,
    ) -> bool;

    /// A 1-RTT packet was processed: a server's open `keys` retire, to be
    /// dropped a while later (RFC 9001 §4.9.3); a client's stay as they
    /// are. What happened, when the keys started to retire.
    #[must_use = "what happened is to be published in the lend"]
    fn retire_zero_rtt<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &mut Self::OwnZeroRttKeys<B, I>,
    ) -> Option<Happened<component_events::KeysRetiring<component_events::level::ZeroRtt>>>;

    /// Whether a HANDSHAKE_DONE frame waits to be sent now, as `own` keeps
    /// it: a server's from the completion of its handshake until it is
    /// written, and again while a frame of it is lost and none is
    /// acknowledged; never a client's.
    fn handshake_done_waiting(own: &Self::Own) -> bool;

    /// The intent of the NEW_TOKEN frames that wait to be sent now, as
    /// `tokens` keeps them: a server's from the issue of a token until it is
    /// written, and again while a frame of it is lost and none is
    /// acknowledged; never a client's.
    fn new_token_waiting(tokens: &Self::NewTokens) -> Option<NewTokenIntent>;

    /// The Token field of the Initial packets this side sends now, which
    /// `own` keeps.
    ///
    /// A server's is always empty (RFC 9000 §17.2.2). A client's is the
    /// token the connection attempt started with, or the one of the Retry
    /// it went on after: every Initial packet of the attempt carries it,
    /// those sent again too (§8.1.3, §17.2.5.3).
    fn initial_token(own: &Self::Own) -> Bytes;

    /// The peer gave a NEW_TOKEN frame with `token`, which `own` takes.
    ///
    /// A client hands each token to where its tokens go, once: a token
    /// that comes again, as when a frame was declared lost and sent again,
    /// is dropped (RFC 9000 §19.7). A server never gets here: a NEW_TOKEN
    /// frame it receives is not permitted
    /// ([`FrameNotPermittedError::NotForRole`](dispatch::FrameNotPermittedError::NotForRole)).
    fn on_new_token(own: &mut Self::Own, token: Bytes);

    /// A valid Retry `retry` with `token` arrived: whether the connection
    /// attempt goes on, as the Retry policy `own` keeps decides. Going on,
    /// `own` keeps `token` for every later Initial packet (RFC 9000
    /// §17.2.5.3).
    ///
    /// Only a client receives a Retry: a server drops one, and never gets
    /// here.
    fn on_retry(own: &mut Self::Own, retry: &ReceivedRetry, token: Bytes) -> RetryDecision;

    /// The Initial secrets split into this side's sending and receiving
    /// secret, in that order (RFC 9001 §5.2).
    fn split_initial_secrets(secrets: InitialSecrets) -> (TrafficSecret, TrafficSecret);

    /// Whether the address of a logical link that comes after the first is
    /// validated when its entry is made.
    ///
    /// A server's is not: it is an address the peer moved to (RFC 9000 §8,
    /// §9.3). A client's is: the limit applies only to answering packets
    /// from an address not yet validated, not to a client starting a
    /// connection or a migration (§21.1.1.1).
    fn later_link_validation() -> AddressValidation;

    /// Whether this side takes its address as validated by the peer from
    /// the start (RFC 9002 Appendix A.8).
    ///
    /// A server does: a client validates the server's address implicitly. A
    /// client does not until the server acknowledges one of its Handshake
    /// packets or the handshake is confirmed; until then it keeps a probe
    /// timeout even with nothing in flight (§6.2.2.1), so that a lost
    /// server flight cannot leave both sides waiting.
    fn peer_validates_address_implicitly() -> bool;

    /// The connection ID this side sends with before the peer chose its
    /// own for the handshake, from `client_dcid`, the Destination
    /// Connection ID the connection was made with.
    ///
    /// A client's is that one, which it chose (RFC 9000 §7.2). A server has
    /// none: it sends nothing before the client's first Initial packet
    /// opens.
    fn initial_destination_connection_id(client_dcid: ConnectionId) -> Option<ConnectionId>;
}

/// The server's side, with the handshake engine whose start state is
/// `Tls` and the issuer `Ti` of the tokens of its NEW_TOKEN frames
/// ([`ConnectionNewTokenIssuer`](address_token::ConnectionNewTokenIssuer)).
pub struct Server<Tls, Ti>(Marker<(Tls, Ti)>);

impl<Tls, Ti> Debug for Server<Tls, Ti> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Server")
    }
}

impl<Tls, Ti> Side for Server<Tls, Ti>
where
    Tls: ServerHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    Tls::Target: 'static,
    Ti: 'static,
{
    const ROLE: Role = Role::Server;
    type Tls = Tls;
    type Advancing = ServerAdvancingKind<Tls>;
    type Exporter = Exporter<Tls::Crypto>;
    type HandshakeFacts = ServerHandshakeFacts<Tls::Target>;
    type LayerSelection = SelectedTarget<Tls::Target>;
    type AlertError = Tls::AlertError;
    type Start = ServerOnlyStart<Ti>;
    type Own = HandshakeDoneSource;
    type NewTokens = NewTokenSource<Ti>;
    type OwnZeroRttKeys<B: CryptoBackend + 'static, I: Copy + Ord + 'static> =
        ZeroRttReceiving<B, I>;
    fn zero_rtt_receive_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &ZeroRttReceiving<B, I>,
    ) -> ZeroRttReceiveKeys<'_, B> {
        keys.receive_keys()
    }
    fn zero_rtt_send_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        _: &ZeroRttReceiving<B, I>,
    ) -> Option<&DirectionKeys<B>> {
        None
    }
    fn zero_rtt_awaits_retirement<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &ZeroRttReceiving<B, I>,
    ) -> bool {
        matches!(keys, ZeroRttReceiving::Open(_))
    }
    fn retire_zero_rtt<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &mut ZeroRttReceiving<B, I>,
    ) -> Option<Happened<component_events::KeysRetiring<component_events::level::ZeroRtt>>> {
        keys.retire()
    }
    fn handshake_done_waiting(own: &HandshakeDoneSource) -> bool {
        own.is_waiting()
    }
    fn new_token_waiting(tokens: &NewTokenSource<Ti>) -> Option<NewTokenIntent> {
        tokens.intent()
    }
    fn initial_token(_: &HandshakeDoneSource) -> Bytes {
        Bytes::new()
    }
    fn on_new_token(_: &mut HandshakeDoneSource, _: Bytes) {}
    fn on_retry(_: &mut HandshakeDoneSource, _: &ReceivedRetry, _: Bytes) -> RetryDecision {
        RetryDecision::Abandon
    }
    fn split_initial_secrets(secrets: InitialSecrets) -> (TrafficSecret, TrafficSecret) {
        (secrets.server, secrets.client)
    }
    fn later_link_validation() -> AddressValidation {
        AddressValidation::NotValidated
    }
    fn peer_validates_address_implicitly() -> bool {
        true
    }
    fn initial_destination_connection_id(_: ConnectionId) -> Option<ConnectionId> {
        None
    }
}

/// The client's side, with the handshake engine whose start state is
/// `Tls`, the sink `Tk` of the address validation tokens its server gives
/// it, the Retry policy `Rp` and the connector `Lc` of the links it
/// migrates to ([`LinkConnector`](link_connector::LinkConnector)).
pub struct Client<Tls, Tk, Rp, Lc>(Marker<(Tls, Tk, Rp, Lc)>);

/// What a side type holds of its parameters: nothing.
type Marker<T> = PhantomData<fn() -> T>;

impl<Tls, Tk, Rp, Lc> Debug for Client<Tls, Tk, Rp, Lc> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Client")
    }
}

impl<Tls, Tk, Rp, Lc> Side for Client<Tls, Tk, Rp, Lc>
where
    Tls: ClientHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    Tk: AddressTokenSink + 'static,
    Rp: ClientRetryPolicy + 'static,
    Lc: 'static,
{
    const ROLE: Role = Role::Client;
    type Tls = Tls;
    type Advancing = ClientAdvancingKind<Tls>;
    type Exporter = Exporter<Tls::Crypto>;
    type HandshakeFacts = ClientHandshakeFacts;
    type LayerSelection = Option<ProtocolName<Bytes>>;
    type AlertError = Tls::AlertError;
    type Start = ClientOnlyStart<Tk, Rp, Lc>;
    type Own = ClientOnlyState<Tk, Rp, Lc>;
    type NewTokens = NoNewTokens;
    type OwnZeroRttKeys<B: CryptoBackend + 'static, I: Copy + Ord + 'static> = ZeroRttSending<B>;
    fn zero_rtt_receive_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        _: &ZeroRttSending<B>,
    ) -> ZeroRttReceiveKeys<'_, B> {
        ZeroRttReceiveKeys::Gone
    }
    fn zero_rtt_send_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &ZeroRttSending<B>,
    ) -> Option<&DirectionKeys<B>> {
        keys.send()
    }
    fn zero_rtt_awaits_retirement<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        _: &ZeroRttSending<B>,
    ) -> bool {
        false
    }
    fn retire_zero_rtt<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        _: &mut ZeroRttSending<B>,
    ) -> Option<Happened<component_events::KeysRetiring<component_events::level::ZeroRtt>>> {
        None
    }
    fn handshake_done_waiting(_: &ClientOnlyState<Tk, Rp, Lc>) -> bool {
        false
    }
    fn new_token_waiting(_: &NoNewTokens) -> Option<NewTokenIntent> {
        None
    }
    fn initial_token(own: &ClientOnlyState<Tk, Rp, Lc>) -> Bytes {
        own.initial_token().clone()
    }
    fn on_new_token(own: &mut ClientOnlyState<Tk, Rp, Lc>, token: Bytes) {
        own.new_token(token);
    }
    fn on_retry(
        own: &mut ClientOnlyState<Tk, Rp, Lc>,
        retry: &ReceivedRetry,
        token: Bytes,
    ) -> RetryDecision {
        own.retry(retry, token)
    }
    fn split_initial_secrets(secrets: InitialSecrets) -> (TrafficSecret, TrafficSecret) {
        (secrets.client, secrets.server)
    }
    fn later_link_validation() -> AddressValidation {
        AddressValidation::Validated
    }
    fn peer_validates_address_implicitly() -> bool {
        false
    }
    fn initial_destination_connection_id(client_dcid: ConnectionId) -> Option<ConnectionId> {
        Some(client_dcid)
    }
}

/// What version 1 needs to make the connection node, given once by whoever
/// makes the connection.
pub struct ConnectionArgs<T: Choices, L: LogicalPathKeys> {
    /// The backend the packet protection keys are derived with.
    pub crypto: T::Crypto,
    /// What the connection's handshake starts from: the start state of the
    /// side's handshake engine, which the advancing call takes.
    pub handshake: HandshakeStart<<T::Side as Side>::Tls>,
    /// What only this side's connection starts with besides: a
    /// [`ServerOnlyStart`] for a server, a [`ClientOnlyStart`] for a
    /// client.
    pub side: <T::Side as Side>::Start,
    /// The Destination Connection ID of the client's first Initial packet,
    /// which the Initial secrets are derived from (RFC 9001 §5.2): the one a
    /// client chose, the one a server found in the first datagrams.
    pub client_dcid: ConnectionId,
    /// The Destination Connection ID of the client's very first Initial
    /// packet when a server sent a Retry before making the connection, and
    /// `client_dcid` is the Source Connection ID of that Retry: the
    /// `original_destination_connection_id` the server sends, with
    /// `client_dcid` as its `retry_source_connection_id` (RFC 9000 §7.3).
    /// `None` without a Retry, and always for a client.
    pub original_destination_connection_id: Option<ConnectionId>,
    /// How many times the bytes received from an address not yet validated
    /// may be sent to it.
    pub anti_amplification: AntiAmplificationFactor,
    /// The transport parameters of version 1 as configured; among them
    /// this side's maximum idle timeout.
    pub transport_parameters: TransportParameterSlots,
    /// What is known about the connection's first logical link.
    pub first_link: LinkFacts,
    /// The configuration the connection's recovery factory is made from.
    pub recovery: RecoveryConfigOf<T, L>,
    /// The thresholds of loss detection, checked against the precision of
    /// the clock's timers.
    pub loss_thresholds: LossThresholds,
    /// How many ranges an ACK frame this side writes reports at most.
    pub max_ack_ranges: MaxAckRanges,
    /// When this side initiates a 1-RTT key update, as far as the packets
    /// sealed with one generation go.
    pub key_update: KeyUpdateThreshold,
    /// How much CRYPTO data each encryption level holds past what the
    /// handshake engine has read, for this side's role.
    pub crypto_receive: CryptoReceiveCapacities,
    /// The first flight: the first datagrams, or what reading them before
    /// deciding left.
    pub first_flight: FirstFlight<T>,
    /// The datagram receiver of the connection's initial path.
    pub initial_receiver: InitialPathReceiver<T::Receiver>,
    /// How many inputs, datagrams and held inputs released, the receiving
    /// call of a logical path handles at most in one poll before it yields.
    pub max_datagrams_per_poll: NonZeroUsize,
    /// How many inputs a logical path holds at most until the keys to
    /// process them come.
    pub max_held_inputs: usize,
    /// The configuration each logical path's destination connection ID
    /// strategy is made from.
    pub destination_connection_ids: DestinationConnectionIdConfigOf<T>,
    /// What registers the reset tokens of the peer's connection IDs, as the
    /// endpoint shares it with the router that detects stateless resets.
    pub reset_token_registry: T::ResetTokenRegistry,
    /// The first of this side's connection IDs, with its stateless reset
    /// token: the Source Connection ID of the long headers this side sends.
    pub first_local_connection_id: FirstLocalConnectionId,
    /// What issues this side's connection IDs after the first, with the
    /// registration of the first with routing, which the first logical
    /// path's local connection ID strategy keeps.
    pub local_connection_id_issuer: LocalConnectionIdIssuer<T::ConnectionIdIssuer>,
    /// How many datagrams the sending call of a link path hands to its link
    /// at once at most.
    pub max_datagrams_per_send: NonZeroUsize,
    /// What adjusts the close this endpoint sends at each encryption level.
    pub immediate_close_policy: ImmediateClosePolicyOf<T>,
    /// What decides how version 1's transport parameters go when a server
    /// resumes a connection; a client does not use it.
    pub resumed_parameters_policy: ResumedParametersPolicyOf<T>,
    /// The cell the application's request to close the connection is put
    /// in; the connection node keeps a clone of it, and whoever lets the
    /// application ask keeps another.
    pub close_request: CloseRequestCell<ApplicationErrorOf<T>>,
    /// What the stream set of the established layer is configured with;
    /// the connection node keeps it until the layer is built.
    pub stream_set: StreamSetConfigOf<T>,
    /// What the receiver of the connection's events is made from
    /// ([`HostChoices::Events`]); its default records nothing for
    /// [`NoEvents`](events::NoEvents).
    pub events: EventsConfigOf<T, L>,
}

impl<T: Choices, L: ParametersOf<TransportParameterSpace> + LogicalPathKeys + ConnectionErrorsOf>
    LayerShare<T, L, layer::Connection> for Part
where
    SendTypes<T, L>: HostSendStrategyTypes
        + send_planning::IntakePublishOutcome<
            streams::send::StreamIntent<SendParametersOf<T>>,
            AnyActiveLinkPath,
        >,
{
    type Data = HList![
        InitialKeys<T::Crypto>,
        HandshakeKeys<T::Crypto>,
        OneRttKeys<T::Crypto, InstantOf<T>>,
        OwnZeroRttKeysOf<T>,
        AeadUsage,
        CryptoReceiver<CryptoReceiveBufferOf<T>>,
        CryptoSender<CryptoSendBufferOf<T>>,
        AntiAmplificationFactor,
        FirstLinkStart,
        IdleTimeout<InstantOf<T>>,
        LocalConnectionIdIssuer<T::ConnectionIdIssuer>,
        LocalTransportParameters<TransportParameterSlots>,
        PartResumedParametersPolicy<TransportParameterSlots, ResumedParametersPolicyOf<T>>,
        PeerTransportParameters<TransportParameterSlots<L>>,
        RecoveryFactoryOf<T, L>,
        LossThresholds,
        MaxAckRanges,
        HandshakeConfirmation,
        CloseReasonRecord<CloseCauseOf<T, L>>,
        ConnectionHandleStateOf<T, L>,
        CloseRequestCell<ApplicationErrorOf<T>>,
        DatagramAcceptance,
        InitialPathReceiver<T::Receiver>,
        LogicalPathReceivingLimits,
        FirstFlightStart<T>,
        SendStrategyCore<SendStrategyOf<T, L>>,
        SendStrategyIntake<IntakeOf<T, L>>,
        DestinationConnectionIdConfig<DestinationConnectionIdConfigOf<T>>,
        ConnectionResetTokenRegistry<T::ResetTokenRegistry>,
        FirstLocalConnectionId,
        InitialDestinationConnectionIds,
        PeerHandshakeConnectionId,
        PacketProtectionBackend<T::Crypto>,
        LinkPathSendingLimits,
        ConnectionImmediateClosePolicy<ImmediateClosePolicyOf<T>>,
        <T::Side as Side>::Own,
        <T::Side as Side>::NewTokens,
        ConnectionExporter<<T::Side as Side>::Exporter>,
        StreamSetConfig<StreamSetConfigOf<T>>,
        events::ConnectionEventSink<EventsOf<T, L>>,
    ];
    /// The core of the send strategy and its intake are made together, and
    /// so are the record of why the connection closed and the state of the
    /// connection handle.
    type Units = HList![
        HList![InitialKeys<T::Crypto>],
        HList![HandshakeKeys<T::Crypto>],
        HList![OneRttKeys<T::Crypto, InstantOf<T>>],
        HList![OwnZeroRttKeysOf<T>],
        HList![AeadUsage],
        HList![CryptoReceiver<CryptoReceiveBufferOf<T>>],
        HList![CryptoSender<CryptoSendBufferOf<T>>],
        HList![AntiAmplificationFactor],
        HList![FirstLinkStart],
        HList![IdleTimeout<InstantOf<T>>],
        // it settles the preferred address of the parameters this side
        // sends, which the next takes
        HList![LocalConnectionIdIssuer<T::ConnectionIdIssuer>],
        HList![LocalTransportParameters<TransportParameterSlots>],
        HList![PartResumedParametersPolicy<
            TransportParameterSlots,
            ResumedParametersPolicyOf<T>,
        >],
        HList![PeerTransportParameters<TransportParameterSlots<L>>],
        HList![RecoveryFactoryOf<T, L>],
        HList![LossThresholds],
        HList![MaxAckRanges],
        HList![HandshakeConfirmation],
        HList![CloseReasonRecord<CloseCauseOf<T, L>>, ConnectionHandleStateOf<T, L>],
        HList![CloseRequestCell<ApplicationErrorOf<T>>],
        HList![DatagramAcceptance],
        HList![InitialPathReceiver<T::Receiver>],
        HList![LogicalPathReceivingLimits],
        HList![FirstFlightStart<T>],
        HList![
            SendStrategyCore<SendStrategyOf<T, L>>,
            SendStrategyIntake<IntakeOf<T, L>>
        ],
        HList![DestinationConnectionIdConfig<DestinationConnectionIdConfigOf<T>>],
        HList![ConnectionResetTokenRegistry<T::ResetTokenRegistry>],
        HList![FirstLocalConnectionId],
        HList![InitialDestinationConnectionIds],
        HList![PeerHandshakeConnectionId],
        HList![PacketProtectionBackend<T::Crypto>],
        HList![LinkPathSendingLimits],
        HList![ConnectionImmediateClosePolicy<ImmediateClosePolicyOf<T>>],
        HList![<T::Side as Side>::Own],
        HList![<T::Side as Side>::NewTokens],
        HList![ConnectionExporter<<T::Side as Side>::Exporter>],
        HList![StreamSetConfig<StreamSetConfigOf<T>>],
        HList![events::ConnectionEventSink<EventsOf<T, L>>],
    ];
    type Calls = HList![<T::Side as Side>::Advancing];
    type Args = ConnectionArgs<T, L>;
    /// What the connection handle's state keeps.
    type Remains = ConnectionHandleRemainsOf<T, L>;
}
impl<T: Choices, L> LayerShare<T, L, layer::LinkEntry> for Part {
    type Data = HList![LinkClone<T::Link>, LinkFacts, AntiAmplification];
    type Calls = HList![LinkCeilingWatchingKind, LinkEndWatchingKind];
}
impl<T: Choices, L: FeedbackSummariesOf + LogicalPathKeys + 'static>
    LayerShare<T, L, layer::LogicalPath> for Part
{
    type Data = HList![
        PacketNumberSpaces<PacketNumberSpaceState>,
        PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>,
        AckObligationsOf<T>,
        SendJournalsOf<T, L>,
        LogicalPathInput<T::Link, T::Receiver>,
        KeyPhaseNumbers,
        Arc<StatelessResetSignal>,
        ConnectionIdsOf<T>,
        PacketNumberSpaceRetirement,
        migration::rules::ConnectionMigrationOf<T>,
    ];
    type Calls = HList![
        LogicalPathReceivingKind,
        preferred_address::PreferredAddressMigratingKind
    ];
}
impl<T: Choices, L> LayerShare<T, L, layer::LinkPath> for Part
where
    SendTypes<T, L>: HostSendStrategyTypes,
{
    type Data = HList![
        LinkPathPlannerOf<T, L>,
        LinkPathResetTokenRegistrar<ResetTokenRegistrarOf<T>>,
        LinkPathRole<InstantOf<T>>,
        ClosePacket,
        PendingPathResponse,
        PendingProbePings,
        PendingPmtuProbe,
        migration::rules::LinkPathMigrationOf<T>,
        connection_ids::LocalConnectionIdUsedByPeer,
        path_validation::PathValidationOf<T>,
    ];
    type Calls = HList![LinkPathSendingKind];
}
/// The established layer holds the stream set.
impl<T: Choices, L: ConnectionErrorsOf> LayerShare<T, L, layer::Established> for Part
where
    SendTypes<T, L>: send_planning::IntakePublishOutcome<
            streams::send::StreamIntent<SendParametersOf<T>>,
            AnyActiveLinkPath,
        >,
{
    type Data = HList![StreamsOf<T, L>];
    type Calls = HNil;
}
/// The frame sources of the streams find the stream set of the established
/// layer.
impl<T: Choices, L: ConnectionErrorsOf> EstablishedSourceComponentsPart<T, L> for Part
where
    SendTypes<T, L>: send_planning::IntakePublishOutcome<
            streams::send::StreamIntent<SendParametersOf<T>>,
            AnyActiveLinkPath,
        >,
{
    type Components = HList![StreamsOf<T, L>];
}
/// The loss detection state comes before the probe timeout: its time
/// threshold is dispatched first (RFC 9002 §6.2.1, Appendix A.8).
impl<T: Choices, L: LogicalPathKeys> LayerShare<T, L, layer::Recovery> for Part
where
    RecoveryFactoryOf<T, L>: for<'s> LendCongestion<InstantOf<T>, OthersOf<'s, T, L>>,
{
    type Data = HList![
        RttOf<T, L>,
        CongestionPartOf<T, L>,
        PmtuOf<T, L>,
        LinkPathCongestionState<InstantOf<T>>,
        LinkPathEcnState<InstantOf<T>>,
        LossDetectionOf<T, L>,
        ProbeTimeout<InstantOf<T>>,
    ];
    /// The factory makes the first three together.
    type Units = HList![
        HList![RttOf<T, L>, CongestionPartOf<T, L>, PmtuOf<T, L>],
        HList![LinkPathCongestionState<InstantOf<T>>],
        HList![LinkPathEcnState<InstantOf<T>>],
        HList![LossDetectionOf<T, L>],
        HList![ProbeTimeout<InstantOf<T>>],
    ];
    type Calls = HNil;
}

/// Version 1's facts among the facts of the connection node.
fn own_args<T: Choices, L, I>(
    args: &mut ArgsOf<T, L, layer::Connection>,
) -> &mut ConnectionArgs<T, L>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    args.get_mut()
}

/// The maximum idle timeout among version 1's transport parameters:
/// `None` when it is absent or zero.
fn max_idle_timeout<S: Selector<Option<MaxIdleTimeout>, I>, I>(slots: &S) -> Option<Duration> {
    let millis = u64::from(slots.get().as_ref()?.get());
    Some(Duration::from_millis(millis)).filter(|timeout| !timeout.is_zero())
}

/// The current probe timeout (RFC 9002 §6.2.1): the largest among the link
/// paths with a recovery layer, without backoff, as in the Application
/// Data space, with the peer's maximum ACK delay or the default before its
/// transport parameters are known; `None` when no link path has a recovery
/// layer. The idle timeout and the closing and draining periods are
/// measured in it.
fn current_probe_timeout<'v, 's, T: Choices, L, B: CallBundle, Ima, Ir>(
    peer: &PeerTransportParameters<TransportParameterSlots<L>>,
    thresholds: &LossThresholds,
    others: &'s mut OtherNodes<'v, T, L, B>,
) -> Option<Duration>
where
    for<'x> L: LineageLists<'x, T>,
    L: ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Ir>,
{
    let peer_max_ack_delay = peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
    largest_probe_timeout::<T, L, B, Ir>(peer_max_ack_delay, thresholds.granularity(), others)
}

/// [`current_probe_timeout`], from the peer's maximum ACK delay and the
/// timer granularity as they are.
fn largest_probe_timeout<'v, 's, T: Choices, L, B: CallBundle, Ir>(
    peer_max_ack_delay: Duration,
    granularity: Duration,
    others: &'s mut OtherNodes<'v, T, L, B>,
) -> Option<Duration>
where
    for<'x> L: LineageLists<'x, T>,
    NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Ir>,
{
    let mut pto = None;
    others.each_recovery_read::<RttOf<T, L>, Ir>(|_, rtt| {
        let Some(rtt) = rtt else { return };
        let this = probe_timeout(
            &rtt.estimate(),
            granularity,
            PacketNumberSpaceKind::ApplicationData,
            peer_max_ack_delay,
            0,
        );
        pto = Some(pto.map_or(this, |pto: Duration| pto.max(this)));
    });
    pto
}

// ---- the connection node ----

/// The Initial keys are derived when the connection is made, so the level
/// is live from the start (RFC 9001 §5.2); a first flight read before the
/// connection was made gives the keys it was read with.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for InitialKeys<T::Crypto>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args = own_args::<T, L, I>(args);
        if let Some(keys) = args.first_flight.take_initial_keys() {
            return keys;
        }
        let secrets = InitialSecrets::derive(&args.crypto, &args.client_dcid);
        let (send, receive) = T::Side::split_initial_secrets(secrets);
        InitialKeys::Live(Box::new(LevelKeys {
            send: DirectionKeys::derive(&args.crypto, INITIAL_AEAD, &send),
            receive: DirectionKeys::derive(&args.crypto, INITIAL_AEAD, &receive),
        }))
    }
}

macro_rules! not_yet {
    ($($ty:ident),*) => {$(
        /// The handshake produces them later.
        impl<T: Choices, L> Build<T, L, layer::Connection, ()> for $ty<T::Crypto>
        where
            L: LineagePartList<T>,
        {
            fn build<'v>(
                _: &mut ParentsOf<'v, T, L, layer::Connection>,
                _: &mut ArgsOf<T, L, layer::Connection>,
            ) -> Self {
                $ty::NotYet
            }
        }
    )*};
}
not_yet!(HandshakeKeys);

/// The handshake produces them later.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for OneRttKeys<T::Crypto, InstantOf<T>>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        OneRttKeys::NotYet
    }
}

/// A server decides whether it accepts 0-RTT when it writes its
/// ServerHello; until then 0-RTT packets wait.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for ZeroRttReceiving<T::Crypto, InstantOf<T>>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        ZeroRttReceiving::NotYet
    }
}

/// This version's client offers no 0-RTT.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for ZeroRttSending<T::Crypto>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        ZeroRttSending::None
    }
}
/// It has no deadline and subscribes to nothing.
impl<B: CryptoBackend> PassiveDataComponent for ZeroRttSending<B> {}

/// Nothing is sealed or opened when the connection is made; a key update
/// is due as the connection's arguments say.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for AeadUsage
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        AeadUsage::with_threshold(own_args::<T, L, I>(args).key_update)
    }
}
/// It has no deadline and subscribes to nothing; the calls that seal and open
/// packets count in it.
impl PassiveDataComponent for AeadUsage {}

/// The connection keeps a clone of the backend it was made with.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for PacketProtectionBackend<T::Crypto>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        PacketProtectionBackend(own_args::<T, L, I>(args).crypto.clone())
    }
}
/// It has no deadline and subscribes to nothing; the keys of the later levels are
/// derived with it.
impl<B> PassiveDataComponent for PacketProtectionBackend<B> {}

/// What the keys of a level do as the connection closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClosingKeys {
    /// They stay as they are: the connection is not closing, a link path
    /// has not entered `Closing` or `Draining` yet, or a closing one has
    /// not sealed its close packet.
    Kept,
    /// Only their receiving half stays, to see whether the peer closes too
    /// (RFC 9000 §10.2.1); a level without one is discarded.
    ReceiveOnly,
    /// They are discarded: every link path is draining (§10.2.2).
    Discarded,
}

/// What the keys of a level do, by whether the reason for closing is
/// `written` and by the roles and close packets of the link paths: with
/// every link path draining they are discarded; with the reason written and
/// every link path closing or draining, the closing ones with their close
/// packets sealed, only the receiving half stays. Requiring a role of every
/// link path keeps a key whose handler runs before the roles change from
/// losing its sending half while no link path has sealed yet.
fn closing_keys<T, L, B, J, Jc>(written: bool, others: &mut OtherNodes<'_, T, L, B>) -> ClosingKeys
where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, J> + GetAt<ClosePacket, Jc>,
{
    let (mut any, mut all_draining, mut all_ending) = (false, true, true);
    let mut closing = Vec::new();
    others.each_link_path_read::<LinkPathRole<InstantOf<T>>, J>(|key, role| {
        any = true;
        all_draining &= matches!(role, LinkPathRole::Draining(_));
        match role {
            LinkPathRole::Closing(_) => closing.push(key.clone()),
            LinkPathRole::Draining(_) => {}
            LinkPathRole::Candidate | LinkPathRole::Active | LinkPathRole::Settling(_) => {
                all_ending = false;
            }
        }
    });
    if !any {
        return ClosingKeys::Kept;
    }
    if all_draining {
        return ClosingKeys::Discarded;
    }
    if !written || !all_ending {
        return ClosingKeys::Kept;
    }
    let mut sealed = true;
    others.each_link_path_read::<ClosePacket, Jc>(|key, packet| {
        sealed &= packet.is_sealed() || !closing.contains(key);
    });
    if sealed {
        ClosingKeys::ReceiveOnly
    } else {
        ClosingKeys::Kept
    }
}

macro_rules! kept_while_closing {
    ($($ty:ident => $level:ident),*) => {$(
        /// The keys of a level follow the record of why the connection
        /// closed, the roles of the link paths and their close packets,
        /// subscribing to the reason written, the roles changed and the
        /// close packets changed: they keep only their receiving half once
        /// the reason is written, every link path is `Closing` or
        /// `Draining` and the closing ones have sealed their close packets,
        /// and are discarded once every link path is `Draining` (RFC 9000
        /// §10.2.1, §10.2.2). A level without a receiving half then is
        /// discarded. The connection's events hear of each half that goes.
        impl<T: Choices, L, I, Ic, J, Jc, Iev>
            DataComponent<T, L, layer::Connection, (I, Ic, J, Jc, Iev)> for $ty<T::Crypto>
        where
            L: LineagePartList<T> + ConnectionErrorsOf,
            for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<$ty<T::Crypto>, I>
                + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
                + GetAt<events::ConnectionEventSink<EventsOf<T, L>>, Iev>,
            for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
            for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
                GetAt<LinkPathRole<InstantOf<T>>, J> + GetAt<ClosePacket, Jc>,
        {
            fn subscribes(out: &mut EventSubscriptions) {
                subscribe_closing(out);
            }
            fn on_events<'v, B: CallBundle>(
                _: TriggeredEvents<'_>,
                mut lineage: LineageOf<'v, T, L, layer::Connection>,
                others: &mut OtherNodes<'v, T, L, B>,
                now: InstantOf<T>,
            ) -> Option<RequestOf<T, L>> {
                let keys = lineage.get::<$ty<T::Crypto>, I>();
                if matches!(keys, $ty::Discarded) {
                    return None;
                }
                let before = [keys.send().is_some(), keys.receive().is_some()];
                let receive_only = matches!(keys, $ty::ReceiveOnly(_));
                let written = lineage
                    .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                    .is_written();
                match closing_keys::<T, L, B, J, Jc>(written, others) {
                    ClosingKeys::Kept => {}
                    ClosingKeys::ReceiveOnly if receive_only => {}
                    ClosingKeys::ReceiveOnly => {
                        let discarded = lineage.get_mut::<$ty<T::Crypto>, I>().keep_receive_only();
                        publish_some(&mut lineage, discarded);
                    }
                    ClosingKeys::Discarded => {
                        let discarded = lineage.get_mut::<$ty<T::Crypto>, I>().discard();
                        publish_some(&mut lineage, discarded);
                    }
                }
                let keys = lineage.get::<$ty<T::Crypto>, I>();
                let after = [keys.send().is_some(), keys.receive().is_some()];
                closing_keys_discarded::<T, L, Iev>(
                    &mut lineage,
                    now,
                    sakuya_wire::v1::encryption_level::EncryptionLevel::$level,
                    before,
                    after,
                );
                None
            }
        }
    )*};
}

/// What the keys of every level subscribe to as the connection closes: the
/// reason written, the roles of the link paths changed and their close
/// packets changed.
fn subscribe_closing(out: &mut EventSubscriptions) {
    out.add::<CloseReasonWritten>()
        .add::<LinkPathRoleChanged>()
        .add::<ClosePacketChanged>();
}

/// Give the connection's events, at `now`, each half of the keys of `level`
/// that the connection's closing discarded: there `before` and gone
/// `after`, each the sending half and the receiving half, in that order.
fn closing_keys_discarded<T, L, Iev>(
    lineage: &mut LineageOf<'_, T, L, layer::Connection>,
    now: InstantOf<T>,
    level: sakuya_wire::v1::encryption_level::EncryptionLevel,
    before: [bool; 2],
    after: [bool; 2],
) where
    T: Choices,
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<events::ConnectionEventSink<EventsOf<T, L>>, Iev>,
{
    if !<EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::ENABLED {
        return;
    }
    let mut sink = lineage.get_mut::<events::ConnectionEventSink<EventsOf<T, L>>, Iev>();
    let Some(receiver) = sink.active::<InstantOf<T>>() else {
        return;
    };
    // this side protects what it sends, the peer what this side receives
    let own = <T::Side as Side>::ROLE;
    for (sender, (was, is)) in [own, own.peer()]
        .into_iter()
        .zip(before.into_iter().zip(after))
    {
        if was && !is {
            events::ConnectionEvents::key_discarded(
                receiver,
                now,
                events::KeyChange::new(level, sender),
            );
        }
    }
}

/// Publish what happened, if anything did, through `lineage`.
fn publish_some<E, V>(lineage: &mut crate::take::Lineage<'_, V>, happened: Option<Happened<E>>)
where
    E: crate::component_event::ComponentEvent,
{
    if let Some(happened) = happened {
        lineage.publish(happened);
    }
}
kept_while_closing!(InitialKeys => Initial);

/// The Handshake keys follow the record of why the connection closed, the
/// roles of the link paths and their close packets, as the Initial keys
/// do; and they subscribe to the handshake confirmed: once it is, they are
/// discarded (RFC 9001 §4.9.2).
impl<T: Choices, L, I, Ic, J, Jc, If, Iev>
    DataComponent<T, L, layer::Connection, (I, Ic, J, Jc, If, Iev)> for HandshakeKeys<T::Crypto>
where
    L: LineagePartList<T> + ConnectionErrorsOf,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<HandshakeKeys<T::Crypto>, I>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<HandshakeConfirmation, If>
        + GetAt<events::ConnectionEventSink<EventsOf<T, L>>, Iev>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, J> + GetAt<ClosePacket, Jc>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        subscribe_closing(out);
        out.add::<HandshakeConfirmed>();
    }
    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let keys = lineage.get::<HandshakeKeys<T::Crypto>, I>();
        if matches!(keys, HandshakeKeys::Discarded) {
            return None;
        }
        if *lineage.get::<HandshakeConfirmation, If>() == HandshakeConfirmation::Confirmed {
            let discarded = lineage.get_mut::<HandshakeKeys<T::Crypto>, I>().discard();
            publish_some(&mut lineage, discarded);
            if <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::ENABLED
                && let Some(receiver) = lineage
                    .get_mut::<events::ConnectionEventSink<EventsOf<T, L>>, Iev>()
                    .active::<InstantOf<T>>()
            {
                for sender in [Role::Client, Role::Server] {
                    let level = sakuya_wire::v1::encryption_level::EncryptionLevel::Handshake;
                    events::ConnectionEvents::key_discarded(
                        receiver,
                        now,
                        events::KeyChange::new(level, sender),
                    );
                }
            }
            return None;
        }
        let before = [keys.send().is_some(), keys.receive().is_some()];
        let receive_only = matches!(keys, HandshakeKeys::ReceiveOnly(_));
        let written = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .is_written();
        match closing_keys::<T, L, B, J, Jc>(written, others) {
            ClosingKeys::Kept => {}
            ClosingKeys::ReceiveOnly if receive_only => {}
            ClosingKeys::ReceiveOnly => {
                let discarded = lineage
                    .get_mut::<HandshakeKeys<T::Crypto>, I>()
                    .keep_receive_only();
                publish_some(&mut lineage, discarded);
            }
            ClosingKeys::Discarded => {
                let discarded = lineage.get_mut::<HandshakeKeys<T::Crypto>, I>().discard();
                publish_some(&mut lineage, discarded);
            }
        }
        let keys = lineage.get::<HandshakeKeys<T::Crypto>, I>();
        let after = [keys.send().is_some(), keys.receive().is_some()];
        closing_keys_discarded::<T, L, Iev>(
            &mut lineage,
            now,
            sakuya_wire::v1::encryption_level::EncryptionLevel::Handshake,
            before,
            after,
        );
        None
    }
}

/// The 1-RTT keys follow the record of why the connection closed, the
/// roles of the link paths and their close packets, as the keys of the
/// other levels do: once the closing link paths have sealed their close
/// packets they keep only their receiving half, and once every link path
/// is `Draining` they are discarded (RFC 9000 §10.2.1, §10.2.2).
///
/// They also subscribe to their key phase changed. Once the next receiving
/// generation became current, the previous one is kept for three current
/// probe timeouts (RFC 9001 §6.5): the largest among the link paths with a
/// recovery layer, as the idle timeout measures it, or the last one the
/// idle timeout took when no link path has one, measured when the keys are
/// looked at after the promotion. That instant is their deadline; when it
/// comes the previous generation is dropped.
impl<T: Choices, L, I, Ic, J, Jc, Iv, Ima, Ir, Iev>
    DataComponent<T, L, layer::Connection, ((I, Ic, J, Jc, Iv), (Ima, Ir, Iev))>
    for OneRttKeys<T::Crypto, InstantOf<T>>
where
    L: LineagePartList<T> + ConnectionErrorsOf,
    L: ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, I>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<events::ConnectionEventSink<EventsOf<T, L>>, Iev>
        + ReadEach<OneRttKeysReads<T, L>, Iv>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, J> + GetAt<ClosePacket, Jc>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Ir>,
{
    const DEADLINE: bool = true;
    fn subscribes(out: &mut EventSubscriptions) {
        subscribe_closing(out);
        out.add::<KeyPhaseChanged>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Connection>) -> Option<InstantOf<T>> {
        lineage
            .get::<OneRttKeys<T::Crypto, InstantOf<T>>, I>()
            .previous_deadline()
    }
    fn expire<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        lineage
            .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, I>()
            .discard_previous();
        None
    }
    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let keys = lineage.get::<OneRttKeys<T::Crypto, InstantOf<T>>, I>();
        if matches!(keys, OneRttKeys::Discarded) {
            return None;
        }
        let before = [keys.send().is_some(), keys.receive().is_some()];
        let receive_only = matches!(keys, OneRttKeys::ReceiveOnly(_));
        let written = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .is_written();
        let level = sakuya_wire::v1::encryption_level::EncryptionLevel::OneRtt;
        match closing_keys::<T, L, B, J, Jc>(written, others) {
            ClosingKeys::Kept => {}
            ClosingKeys::ReceiveOnly if receive_only => {}
            ClosingKeys::ReceiveOnly => {
                let mut keys = lineage.get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, I>();
                let discarded = keys.keep_receive_only();
                let gone = matches!(*keys, OneRttKeys::Discarded);
                let after = [keys.send().is_some(), keys.receive().is_some()];
                publish_some(&mut lineage, discarded);
                closing_keys_discarded::<T, L, Iev>(&mut lineage, now, level, before, after);
                if gone {
                    return None;
                }
            }
            ClosingKeys::Discarded => {
                let discarded = lineage
                    .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, I>()
                    .discard();
                publish_some(&mut lineage, discarded);
                closing_keys_discarded::<T, L, Iev>(&mut lineage, now, level, before, [false; 2]);
                return None;
            }
        }
        if lineage
            .get::<OneRttKeys<T::Crypto, InstantOf<T>>, I>()
            .previous_awaits_deadline()
        {
            let frunk_core::hlist_pat![peer, thresholds, idle] =
                lineage.read_each::<OneRttKeysReads<T, L>, Iv>();
            let pto = current_probe_timeout::<T, L, B, Ima, Ir>(peer, thresholds, others)
                // with no recovery layer, the last one the idle timeout took
                .unwrap_or_else(|| idle.probe_timeout());
            // an instant beyond what the instant type represents is none:
            // the previous generation goes at once rather than never
            let at = now.checked_add(pto.saturating_mul(3)).unwrap_or(now);
            lineage
                .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, I>()
                .set_previous_deadline(at);
        }
        None
    }
}

/// A server's 0-RTT keys follow the record of why the connection closed,
/// the roles of the link paths and their close packets, as the keys of the
/// other levels do: once every link path is `Draining` they are discarded
/// (RFC 9000 §10.2.2); they only receive, so closing leaves them as they
/// are. Whether 0-RTT is accepted is decided when the ServerHello is
/// written: a connection whose reason for closing is written before that
/// refuses it, and the 0-RTT packets that wait are dropped.
///
/// They also subscribe to their own retiring. Once a 1-RTT packet was
/// processed they retire, and are kept for three current probe timeouts, as
/// RFC 9001 §4.9.3 recommends: the largest among the link paths with a
/// recovery layer, as the idle timeout measures it, or the last one the
/// idle timeout took when no link path has one, measured when the keys are
/// looked at after they started to retire. That instant is their deadline;
/// when it comes the keys are discarded.
impl<T: Choices, L, I, Ic, J, Jc, Iv, Iev, Ima, Ir>
    DataComponent<T, L, layer::Connection, ((I, Ic, J, Jc, Iv, Iev), (Ima, Ir))>
    for ZeroRttReceiving<T::Crypto, InstantOf<T>>
where
    L: LineagePartList<T> + ConnectionErrorsOf,
    L: ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ZeroRttReceiving<T::Crypto, InstantOf<T>>, I>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + ReadEach<OneRttKeysReads<T, L>, Iv>
        + GetAt<events::ConnectionEventSink<EventsOf<T, L>>, Iev>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, J> + GetAt<ClosePacket, Jc>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Ir>,
{
    const DEADLINE: bool = true;
    fn subscribes(out: &mut EventSubscriptions) {
        subscribe_closing(out);
        out.add::<KeysRetiring<level::ZeroRtt>>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Connection>) -> Option<InstantOf<T>> {
        lineage
            .get::<ZeroRttReceiving<T::Crypto, InstantOf<T>>, I>()
            .deadline()
    }
    fn expire<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        discard_zero_rtt::<T, L, I, Iev>(&mut lineage, now);
        None
    }
    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let keys = lineage.get::<ZeroRttReceiving<T::Crypto, InstantOf<T>>, I>();
        if matches!(keys, ZeroRttReceiving::None) {
            return None;
        }
        let not_yet = matches!(keys, ZeroRttReceiving::NotYet);
        let written = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .is_written();
        if closing_keys::<T, L, B, J, Jc>(written, others) == ClosingKeys::Discarded {
            discard_zero_rtt::<T, L, I, Iev>(&mut lineage, now);
            return None;
        }
        if written && not_yet {
            let refused = lineage
                .get_mut::<ZeroRttReceiving<T::Crypto, InstantOf<T>>, I>()
                .refuse();
            publish_some(&mut lineage, refused);
            return None;
        }
        if lineage
            .get::<ZeroRttReceiving<T::Crypto, InstantOf<T>>, I>()
            .awaits_deadline()
        {
            let frunk_core::hlist_pat![peer, thresholds, idle] =
                lineage.read_each::<OneRttKeysReads<T, L>, Iv>();
            let pto = current_probe_timeout::<T, L, B, Ima, Ir>(peer, thresholds, others)
                // with no recovery layer, the last one the idle timeout took
                .unwrap_or_else(|| idle.probe_timeout());
            // an instant beyond what the instant type represents is none:
            // the keys go at once rather than never
            let at = now.checked_add(pto.saturating_mul(3)).unwrap_or(now);
            lineage
                .get_mut::<ZeroRttReceiving<T::Crypto, InstantOf<T>>, I>()
                .set_deadline(at);
        }
        None
    }
}

/// Discard a server's 0-RTT keys at `now`; the connection's events hear of
/// it when there were keys to discard.
fn discard_zero_rtt<T, L, I, Iev>(
    lineage: &mut LineageOf<'_, T, L, layer::Connection>,
    now: InstantOf<T>,
) where
    T: Choices,
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ZeroRttReceiving<T::Crypto, InstantOf<T>>, I>
        + GetAt<events::ConnectionEventSink<EventsOf<T, L>>, Iev>,
{
    let keys = lineage.get::<ZeroRttReceiving<T::Crypto, InstantOf<T>>, I>();
    let had_keys = matches!(
        keys,
        ZeroRttReceiving::Open(_) | ZeroRttReceiving::Retiring(..)
    );
    let discarded = lineage
        .get_mut::<ZeroRttReceiving<T::Crypto, InstantOf<T>>, I>()
        .discard();
    publish_some(lineage, discarded);
    if had_keys
        && <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::ENABLED
        && let Some(receiver) = lineage
            .get_mut::<events::ConnectionEventSink<EventsOf<T, L>>, Iev>()
            .active::<InstantOf<T>>()
    {
        let key = events::KeyChange::new(
            sakuya_wire::v1::encryption_level::EncryptionLevel::ZeroRtt,
            Role::Client,
        );
        events::ConnectionEvents::key_discarded(receiver, now, key);
    }
}

/// What the 1-RTT keys and a server's 0-RTT keys read to measure the
/// current probe timeout, besides the RTT estimates; they subscribe to no
/// event of these.
type OneRttKeysReads<T, L> = HList![
    PeerTransportParameters<TransportParameterSlots<L>>,
    LossThresholds,
    IdleTimeout<InstantOf<T>>
];

/// Each level this side receives handshake messages at starts with an
/// empty buffer of the configured capacity; the input reads Initial. A
/// first flight read before the connection was made gives the receiver it
/// was read into.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for CryptoReceiver<CryptoReceiveBufferOf<T>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args = own_args::<T, L, I>(args);
        args.first_flight
            .take_crypto_receiver()
            .unwrap_or_else(|| CryptoReceiver::new(&args.crypto_receive))
    }
}
/// It has no deadline and subscribes to nothing; the calls that take frames or feed
/// the handshake engine change it.
impl<B> PassiveDataComponent for CryptoReceiver<B> {}

/// Each level starts with nothing to send; the output writes Initial.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for CryptoSender<CryptoSendBufferOf<T>>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        CryptoSender::new()
    }
}

/// The output subscribes to the keys of each level discarded: once a
/// level's keys are discarded, its CRYPTO data goes with them (RFC 9001
/// §4.9).
impl<T: Choices, L, I, Ii, Ih, Io> DataComponent<T, L, layer::Connection, (I, Ii, Ih, Io)>
    for CryptoSender<CryptoSendBufferOf<T>>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<CryptoSender<CryptoSendBufferOf<T>>, I>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<KeysDiscarded<level::Initial>>()
            .add::<KeysDiscarded<level::Handshake>>()
            .add::<KeysDiscarded<level::OneRtt>>();
    }

    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let discarded = [
            (
                CryptoLevel::Initial,
                matches!(
                    lineage.get::<InitialKeys<T::Crypto>, Ii>(),
                    InitialKeys::Discarded
                ),
            ),
            (
                CryptoLevel::Handshake,
                matches!(
                    lineage.get::<HandshakeKeys<T::Crypto>, Ih>(),
                    HandshakeKeys::Discarded
                ),
            ),
            (
                CryptoLevel::OneRtt,
                matches!(
                    lineage.get::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>(),
                    OneRttKeys::Discarded
                ),
            ),
        ];
        for (level, discarded) in discarded {
            // takes the output only to change it: it does not read itself
            if discarded
                && !lineage
                    .get::<CryptoSender<CryptoSendBufferOf<T>>, I>()
                    .is_discarded(level)
            {
                let discarded = lineage
                    .get_mut::<CryptoSender<CryptoSendBufferOf<T>>, I>()
                    .discard(level);
                publish_some(&mut lineage, discarded);
            }
        }
        None
    }
}

impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for AntiAmplificationFactor
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        own_args::<T, L, I>(args).anti_amplification
    }
}
impl PassiveDataComponent for AntiAmplificationFactor {}

macro_rules! configured {
    ($($ty:ident . $field:ident),*) => {$(
        /// It is the configured value, which stays the same for the life of
        /// the connection.
        impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for $ty
        where
            L: LineagePartList<T>,
            ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
        {
            fn build<'v>(
                _: &mut ParentsOf<'v, T, L, layer::Connection>,
                args: &mut ArgsOf<T, L, layer::Connection>,
            ) -> Self {
                own_args::<T, L, I>(args).$field
            }
        }
        impl PassiveDataComponent for $ty {}
    )*};
}
configured!(LossThresholds.loss_thresholds, MaxAckRanges.max_ack_ranges);

/// The receiver of the connection's events is made when the connection is,
/// from the default of its configuration, named by the client's very first
/// Destination Connection ID.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for events::ConnectionEventSink<EventsOf<T, L>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args = own_args::<T, L, I>(args);
        let start = events::EventsStart {
            role: <T::Side as Side>::ROLE,
            original_destination_connection_id: args
                .original_destination_connection_id
                .unwrap_or(args.client_dcid),
        };
        events::ConnectionEventSink::new(<EventsOf<T, L> as events::ConnectionEvents<
            InstantOf<T>,
        >>::new(&args.events, &start))
    }
    /// A record kept as the connection's future was dropped is written now,
    /// the first instant there is after the drop.
    fn end<'v, B: CallBundle>(
        mut self,
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        others: &mut OtherNodes<'v, T, L, B>,
    ) {
        if <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::ENABLED {
            self.node_ended(others.now());
        }
    }
}
/// When the receiver records anything, the first poll starts the
/// connection.
impl<T: Choices, L, I> DataComponent<T, L, layer::Connection, (I,)>
    for events::ConnectionEventSink<EventsOf<T, L>>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<events::ConnectionEventSink<EventsOf<T, L>>, I>,
{
    const ACTS_BEFORE_CALLS: bool =
        <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::ENABLED;
    fn before_calls<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
        _: &core::task::Waker,
    ) -> Option<RequestOf<T, L>> {
        lineage
            .get_mut::<events::ConnectionEventSink<EventsOf<T, L>>, I>()
            .poll_began(now);
        None
    }
}

/// No connection starts confirmed: the advancing call confirms it.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for HandshakeConfirmation
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        HandshakeConfirmation::NotConfirmed
    }
}
impl PassiveDataComponent for HandshakeConfirmation {}

/// The record subscribes to its own reason written, which whoever finds a
/// reason for closing writes, and to the end of a link path, after which
/// the link paths left are counted. Once it is written, it asks for
/// the established layer to end; once it is written and no link path is
/// left, for the connection to end: each link path ends when its closing or
/// draining period does. An end without such a period, such as the idle
/// timeout's, asks for the connection to end where it writes the reason.
/// When the connection's future is dropped with the record still empty,
/// the reason becomes [`CloseReason::Aborted`] before any node ends, so the
/// end actions read it: [`AbortCause::DriverDropped`]; the connection's
/// events hear of a record they did not hear of yet when the connection
/// node ends, which has an instant. When a panic
/// unwound through the future it becomes [`AbortCause::Panicked`], and no
/// end action runs.
impl<T: Choices, L: ConnectionErrorsOf, I, Iev> DataComponent<T, L, layer::Connection, (I, Iev)>
    for CloseReasonRecord<CloseCauseOf<T, L>>
where
    L: LineagePartList<T>,
    ConnectionErrorOf<L>: close::TransportClose,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, I>
        + GetAt<events::ConnectionEventSink<EventsOf<T, L>>, Iev>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<CloseReasonWritten>()
            .add::<NodeEnding<layer::LinkPath>>();
    }
    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        if !lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, I>()
            .is_written()
        {
            return None;
        }
        connection_closed_into_events::<T, L, I, Iev>(&mut lineage, now);
        if others.link_path_keys().next().is_none() {
            Some(StructureRequest::EndConnection)
        } else if others.has_established() {
            Some(StructureRequest::EndEstablished)
        } else {
            None
        }
    }
    fn future_dropped<'v>(lineage: &mut LineageOf<'v, T, L, layer::Connection>, cause: AbortCause) {
        // published as anywhere else, though nothing is handled after a drop
        let written = lineage
            .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, I>()
            .record(CloseReason::Aborted(cause));
        publish_some(lineage, written);
        // the events hear of it once the connection node ends, which has an
        // instant; after a panic no node ends, and they do not
        if <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::ENABLED
            && let Some(closed) = lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, I>()
                .reason()
                .map(connection_closed_event)
        {
            lineage
                .get_mut::<events::ConnectionEventSink<EventsOf<T, L>>, Iev>()
                .future_dropped::<InstantOf<T>>(closed);
        }
    }
}

/// Give the connection's events the record of why it closed, once it is
/// written, at `now`; the sink keeps only the first.
fn connection_closed_into_events<'v, T, L, Ic, Iev>(
    lineage: &mut LineageOf<'v, T, L, layer::Connection>,
    now: InstantOf<T>,
) where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    ConnectionErrorOf<L>: close::TransportClose,
    for<'x> <L as LineageLists<'x, T>>::Connection: GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<events::ConnectionEventSink<EventsOf<T, L>>, Iev>,
{
    if <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::ENABLED {
        let closed = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .reason()
            .map(connection_closed_event);
        if let Some(closed) = closed {
            lineage
                .get_mut::<events::ConnectionEventSink<EventsOf<T, L>>, Iev>()
                .record_written(now, || closed);
        }
    }
}

/// What the connection's events say of `reason`, this endpoint's reason
/// for closing or the peer's.
pub(crate) fn connection_closed_event<E, H, A, R>(
    reason: &CloseReason<LocalCloseCause<E, H, A, R>>,
) -> events::ConnectionClosed
where
    E: close::TransportClose,
    H: close::TransportClose,
    A: ApplicationClose,
{
    use events::{CloseTrigger, ConnectionClosed, EventInitiator};
    let (initiator, close, trigger) = match reason {
        CloseReason::Local(cause) => (
            EventInitiator::Local,
            cause.immediate_close(),
            match &**cause {
                LocalCloseCause::Connection(_) | LocalCloseCause::Handshake(_) => {
                    CloseTrigger::Error
                }
                LocalCloseCause::Application(_) => CloseTrigger::Application,
                LocalCloseCause::LinkEnded(_) => CloseTrigger::LinkEnded,
            },
        ),
        CloseReason::Peer(close) => (
            EventInitiator::Remote,
            Some(close.clone()),
            CloseTrigger::PeerClose,
        ),
        CloseReason::IdleTimeout => (EventInitiator::Local, None, CloseTrigger::IdleTimeout),
        CloseReason::StatelessReset => (EventInitiator::Remote, None, CloseTrigger::StatelessReset),
        CloseReason::VersionNegotiation { .. } => {
            (EventInitiator::Remote, None, CloseTrigger::VersionMismatch)
        }
        CloseReason::RetryAbandoned => (EventInitiator::Local, None, CloseTrigger::RetryAbandoned),
        CloseReason::Aborted(_) => (EventInitiator::Local, None, CloseTrigger::Aborted),
    };
    ConnectionClosed {
        initiator,
        close,
        trigger,
    }
}

impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for FirstLinkStart
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        FirstLinkStart::new(own_args::<T, L, I>(args).first_link)
    }
}
impl PassiveDataComponent for FirstLinkStart {}

/// The connection keeps the receiver of its initial path until the first
/// logical path takes it.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for InitialPathReceiver<T::Receiver>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        own_args::<T, L, I>(args).initial_receiver.moved()
    }
}
impl<R> PassiveDataComponent for InitialPathReceiver<R> {}

/// The limits are configured, and stay the same for the life of the
/// connection; each logical path takes them when it is built.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for LogicalPathReceivingLimits
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args = own_args::<T, L, I>(args);
        LogicalPathReceivingLimits {
            max_datagrams_per_poll: args.max_datagrams_per_poll,
            max_held_inputs: args.max_held_inputs,
        }
    }
}
impl PassiveDataComponent for LogicalPathReceivingLimits {}

/// The limits are configured, and stay the same for the life of the
/// connection; the sending call of each link path takes them when it
/// starts.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for LinkPathSendingLimits
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        LinkPathSendingLimits {
            max_datagrams_per_send: own_args::<T, L, I>(args).max_datagrams_per_send,
        }
    }
}
impl PassiveDataComponent for LinkPathSendingLimits {}

/// No datagram is sent when the connection is made.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for DatagramAcceptance
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        DatagramAcceptance::NoneAccepted
    }
}
/// It has no deadline and subscribes to nothing; the sending calls note in it.
impl PassiveDataComponent for DatagramAcceptance {}

/// The connection keeps the close policy it was made with.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for ConnectionImmediateClosePolicy<ImmediateClosePolicyOf<T>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        ConnectionImmediateClosePolicy::new(
            own_args::<T, L, I>(args).immediate_close_policy.clone(),
        )
    }
}
/// It has no deadline and subscribes to nothing; the close packets adjust with it.
impl<P> PassiveDataComponent for ConnectionImmediateClosePolicy<P> {}

/// The connection keeps what its first flight gave the later parts of the
/// tree until they take it. Datagrams not read yet are cut as routing cuts
/// those it delivers under the client's first Destination Connection ID:
/// a short header's is as long as that one.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for FirstFlightStart<T>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let args = own_args::<T, L, I>(args);
        let dcid_len = args.client_dcid.length();
        args.first_flight.take_start(dcid_len)
    }
}
/// It has no deadline and subscribes to nothing; the parts built after the
/// connection node take from it.
impl<T: Choices> PassiveDataComponent for FirstFlightStart<T> {}

/// The idle timeout starts from this side's maximum idle timeout as
/// configured.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)> for IdleTimeout<InstantOf<T>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        IdleTimeout::new(max_idle_timeout(
            &own_args::<T, L, I>(args).transport_parameters,
        ))
    }
}

/// The idle timeout has the deadline the calls restart, and follows both
/// sides' transport parameters (this side's once they are sent, the peer's
/// once they are known) and the RTT estimates of the recovery layers,
/// subscribing to the parameters sent and known, to an RTT sample and to a
/// recovery layer built or ended. Its floor is three probe timeouts: the
/// largest among the link paths with a recovery layer, without backoff, as
/// in the Application Data space. When it expires the connection ends at
/// once, without a closing period (RFC 9000 §10.1), and the reason goes
/// into the record of why the connection closed; a reason already there
/// stays.
impl<T: Choices, L, Ii, Iv, Ic, Is, Ima, Ir, Iev>
    DataComponent<T, L, layer::Connection, ((Ii, Iv, Ic), (Is, Ima, Ir), Iev)>
    for IdleTimeout<InstantOf<T>>
where
    L: LineagePartList<T>,
    L: ParametersOf<TransportParameterSpace> + ConnectionErrorsOf,
    ConnectionErrorOf<L>: close::TransportClose,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<events::ConnectionEventSink<EventsOf<T, L>>, Iev>,
    TransportParameterSlots<L>:
        Selector<Option<MaxIdleTimeout>, Is> + Selector<Option<MaxAckDelay>, Ima>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<IdleTimeout<InstantOf<T>>, Ii>
        + ReadEach<IdleTimeoutReads<L>, Iv>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Ir>,
{
    const DEADLINE: bool = true;
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<PeerTransportParametersKnown>()
            .add::<LocalTransportParametersSent>()
            .add::<RttSampled>()
            .add::<NodeStarted<layer::Recovery>>()
            .add::<NodeEnding<layer::Recovery>>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Connection>) -> Option<InstantOf<T>> {
        lineage.get::<IdleTimeout<InstantOf<T>>, Ii>().deadline()
    }
    fn expire<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let written = lineage
            .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .record(CloseReason::IdleTimeout);
        publish_some(&mut lineage, written);
        // the connection ends at once, before the record's handler runs
        connection_closed_into_events::<T, L, Ic, Iev>(&mut lineage, now);
        Some(StructureRequest::EndConnection)
    }
    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        others: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let frunk_core::hlist_pat![local, peer, thresholds] =
            lineage.read_each::<IdleTimeoutReads<L>, Iv>();
        let pto = current_probe_timeout::<T, L, B, Ima, Ir>(peer, thresholds, others);
        let local = local
            .sent()
            .or(local.configured())
            .and_then(max_idle_timeout);
        let peer = peer.known().map(max_idle_timeout);
        // takes the timeout only to change it
        let idle = lineage.get::<IdleTimeout<InstantOf<T>>, Ii>();
        let peer = peer.unwrap_or(idle.peer());
        // with no recovery layer the last probe timeout stays
        let pto = pto.unwrap_or(idle.probe_timeout());
        if (idle.local(), idle.peer(), idle.probe_timeout()) != (local, peer, pto) {
            let mut idle = lineage.get_mut::<IdleTimeout<InstantOf<T>>, Ii>();
            idle.set_local(local);
            idle.set_peer(peer);
            idle.set_probe_timeout(pto);
        }
        None
    }
}

/// What the idle timeout reads besides itself, the RTT estimates and the
/// record of why the connection closed.
type IdleTimeoutReads<L> = HList![
    LocalTransportParameters<TransportParameterSlots>,
    PeerTransportParameters<TransportParameterSlots<L>>,
    LossThresholds
];

/// This side's transport parameters start as configured.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for LocalTransportParameters<TransportParameterSlots>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        LocalTransportParameters::Configured(own_args::<T, L, I>(args).transport_parameters)
    }
}
impl<S> PassiveDataComponent for LocalTransportParameters<S> {}

/// The policy of version 1's transport parameters on resumption is the one
/// the connection was made with.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for PartResumedParametersPolicy<TransportParameterSlots, ResumedParametersPolicyOf<T>>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        PartResumedParametersPolicy::new(
            own_args::<T, L, I>(args).resumed_parameters_policy.clone(),
        )
    }
}
/// It has no deadline and subscribes to nothing; a server's advancing call asks it
/// once, when it resumes.
impl<S, Pol> PassiveDataComponent for PartResumedParametersPolicy<S, Pol> {}

/// The peer's transport parameters are not known when the connection is
/// made, even to a client that offers 0-RTT: the remembered ones are set
/// when its first ClientHello is written.
impl<T: Choices, L: ParametersOf<TransportParameterSpace>> Build<T, L, layer::Connection, ()>
    for PeerTransportParameters<TransportParameterSlots<L>>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        PeerTransportParameters::NotYet
    }
}
impl<S> PassiveDataComponent for PeerTransportParameters<S> {}

// ---- the logical path ----

/// The first logical path takes the receiver of the initial path, the
/// first datagrams not read yet and the inputs held while the first flight
/// was read; a later one starts without a receiver and with nothing to
/// receive first. Each takes the connection's limits.
impl<T: Choices, L, I, J, Ik> Build<T, L, layer::LogicalPath, (I, J, Ik)>
    for LogicalPathInput<T::Link, T::Receiver>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<InitialPathReceiver<T::Receiver>, I>
        + GetAt<LogicalPathReceivingLimits, J>
        + GetAt<FirstFlightStart<T>, Ik>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        let limits = *parents.get::<LogicalPathReceivingLimits, J>();
        let receiver = parents
            .get_mut::<InitialPathReceiver<T::Receiver>, I>()
            .take();
        let mut start = parents.get_mut::<FirstFlightStart<T>, Ik>();
        let mut input = LogicalPathInput::new(receiver, limits);
        input.start_with(
            start.take_datagrams(),
            start.dcid_len(),
            start.take_held(),
            start.take_received(),
        );
        input
    }
}
impl<Lk: sakuya_link::Link, R: LogicalPathDatagramReceiver<Lk>> PassiveDataComponent
    for LogicalPathInput<Lk, R>
{
}

/// No 1-RTT packet has been seen when a logical path is made.
impl<T: Choices, L> Build<T, L, layer::LogicalPath, ()> for KeyPhaseNumbers
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        KeyPhaseNumbers::new()
    }
}
/// It has no deadline and subscribes to nothing; the calls that seal and open
/// 1-RTT packets note in it.
impl PassiveDataComponent for KeyPhaseNumbers {}

// ---- the entry of a logical link ----

/// The clone is moved from the request for the first link path over the
/// logical link.
impl<T: Choices, L> Build<T, L, layer::LinkEntry, ()> for LinkClone<T::Link>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LinkEntry>,
        args: &mut ArgsOf<T, L, layer::LinkEntry>,
    ) -> Self {
        // invariant: the driver gives every entry the clone, and only this
        // component takes it
        LinkClone(
            args.link
                .take()
                .expect("an entry is given its link's clone once"),
        )
    }
}
impl<Lk> PassiveDataComponent for LinkClone<Lk> {}

/// The first entry takes the facts the connection was made with; a later
/// one starts as the side says.
impl<T: Choices, L, I> Build<T, L, layer::LinkEntry, I> for LinkFacts
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<FirstLinkStart, I>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LinkEntry>,
        _: &mut ArgsOf<T, L, layer::LinkEntry>,
    ) -> Self {
        parents
            .get_mut::<FirstLinkStart, I>()
            .take_facts()
            .unwrap_or(LinkFacts {
                validation: T::Side::later_link_validation(),
            })
    }
}
impl PassiveDataComponent for LinkFacts {}

/// The limit starts with nothing sent, by the configured factor. The first
/// entry starts with the bytes of the first datagrams read before the
/// connection was made (RFC 9000 §8.1); any other starts with nothing
/// received.
impl<T: Choices, L, I, J> Build<T, L, layer::LinkEntry, (I, J)> for AntiAmplification
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<AntiAmplificationFactor, I> + GetAt<FirstFlightStart<T>, J>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LinkEntry>,
        _: &mut ArgsOf<T, L, layer::LinkEntry>,
    ) -> Self {
        let mut limit = AntiAmplification::new(*parents.get::<AntiAmplificationFactor, I>());
        let received = parents
            .get_mut::<FirstFlightStart<T>, J>()
            .take_received_bytes();
        if received > 0 {
            limit.received(received);
        }
        limit
    }
}
impl PassiveDataComponent for AntiAmplification {}

// ---- the link path ----

/// A link path starts in the role its request gives: the connection's
/// first link path is active from the start, as the handshake runs over
/// it.
///
/// When the link path ends, the packets sent on it that were neither
/// acknowledged nor declared lost leave the send journals of its logical
/// path, in every space, and the summaries of their frames go back to
/// their frame sources as lost; the kept records of its lost packets go
/// with them, so a late acknowledgment of them is ignored. When its
/// recovery layer ended with it, its congestion control hears of none of
/// it.
///
/// When its recovery layer moved to another link path of the logical path
/// instead, the layer's loss detection state keeps those packets, and its
/// congestion control counts them in flight until they are acknowledged or
/// declared lost, which then hands nothing back. The marked ones are
/// outstanding in the layer's ECN state no more: they left with the link
/// path, without a signal (RFC 9000 §13.4.2), and a link path that holds
/// for them stops holding.
impl<T: Choices, L, Ij, Hf, Is, Ik> Build<T, L, layer::LinkPath, (Ij, Hf, Is, Ik)>
    for LinkPathRole<InstantOf<T>>
where
    L: LineagePartList<T> + FeedbackSummariesOf + ConnectionErrorsOf,
    SendTypes<T, L>: send_planning::IntakePublishOutcome<
            streams::send::StreamIntent<SendParametersOf<T>>,
            AnyActiveLinkPath,
        >,
    L: EstablishedSourceComponentsOf<T, L>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        crate::take::TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Is>,
    for<'v> <L as LineageLists<'v, T>>::LinkPathParents: GetAt<SendJournalsOf<T, L>, Ij>,
    for<'v> <L as LineageLists<'v, T>>::LinkPathParents:
        LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    RecoveryFactoryOf<T, L>: for<'s> LendCongestion<InstantOf<T>, OthersOf<'s, T, L>>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, LinkPathEndRecoveryTakes<T, L>, Ik>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        args: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        args.role
    }
    fn end<'v, B: CallBundle>(
        self,
        parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
    ) {
        let NodeKey::LinkPath(path, link) = others.here().clone() else {
            unreachable!("an ended link path's others carry its key")
        };
        let identifier = L::link_path_identifier(&path, &link);
        let now = others.now();
        let mut established =
            others.borrow_established_optional::<EstablishedSourceComponentsOfParts<T, L>, Is>();
        let mut marked = Vec::new();
        for space in PacketNumberSpaceKind::ALL {
            let mut all_journals = parents.get_mut::<SendJournalsOf<T, L>, Ij>();
            let Some(journals) = all_journals.get_mut(space) else {
                continue;
            };
            let unsettled: Vec<_> = journals.take_link_path(&identifier).collect();
            // the marked packets the link accepted, which count in the ECN
            // state of the layer whose loss detection state they entered
            let mut numbers: Vec<PacketNumber> = unsettled
                .iter()
                .filter(|record| {
                    record.ecn != EcnMarking::NotEct
                        && matches!(record.state, SentPacketState::Sent(_))
                })
                .map(|record| record.number)
                .collect();
            if !numbers.is_empty() {
                numbers.sort_unstable();
                marked.push((space, numbers));
            }
            LineageFeedback::<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>::lost_each(
                parents,
                &mut established,
                now,
                space,
                unsettled
                    .iter()
                    .filter(|record| !record.content_handed_back)
                    .flat_map(|record| &record.summaries),
            );
        }
        drop(established);
        if marked.is_empty() {
            return;
        }
        // its own layer ended before it; a packet number is sent once in its
        // space, so at most one layer keeps each of them: the one that moved
        // away from it
        let links: Vec<LinkIdOf<T>> = others
            .link_path_keys()
            .filter_map(|key| match key {
                NodeKey::LinkPath(of, other) if *of == path => Some(other.clone()),
                _ => None,
            })
            .collect();
        for other in links {
            others.with_recovery_at::<LinkPathEndRecoveryTakes<T, L>, Ik, _>(
                &path,
                &other,
                |frunk_core::hlist_pat![detections, mut ecn], _| {
                    for (space, numbers) in &marked {
                        let Some(detection) = detections.get(*space) else {
                            continue;
                        };
                        let mut kept = 0u64;
                        for packet in detection.outstanding() {
                            if numbers.binary_search(&packet.number).is_ok() {
                                kept = kept.saturating_add(1);
                            }
                        }
                        ecn.on_link_path_ended(*space, kept);
                    }
                },
            );
        }
    }
}

/// What the end of a link path takes from the recovery layer of each other
/// link path of its logical path: the loss detection states and the ECN
/// state.
type LinkPathEndRecoveryTakes<T, L> = HList![LossDetectionOf<T, L>, LinkPathEcnState<InstantOf<T>>];

/// The role's end time is its deadline: when it comes the link path ends.
/// It subscribes to its own change, which other components make, to the
/// reason for closing written and to its link path built, and asks for the
/// recovery layer to follow the role: built when the link path is `Active`
/// without one, ended when the role has none. A link path built `Active`,
/// the connection's first, so gets its layer as soon as it is built.
///
/// Once the record is written, a candidate ends, and an `Active` or
/// `Settling` link path enters `Closing` for three times the current probe
/// timeout (RFC 9000 §10.2), measured when it enters; a link path already
/// `Closing` or `Draining` keeps its role. Whoever finds that the peer
/// closed puts the link paths into `Draining` itself.
///
/// Connection migration asks for the layer of a link path it makes active
/// itself, with the RTT path validation measured when there is one
/// ([`migration`]); the request here, without an initial RTT, is for a link
/// path that is `Active` without one otherwise.
impl<T: Choices, L, I, Ic, Iv, Ima, Ir>
    DataComponent<T, L, layer::LinkPath, ((I, Ic, Iv), (Ima, Ir))> for LinkPathRole<InstantOf<T>>
where
    L: LineagePartList<T>,
    L: ParametersOf<TransportParameterSpace> + ConnectionErrorsOf,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'v> <L as LineageLists<'v, T>>::LinkPath: GetAt<LinkPathRole<InstantOf<T>>, I>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + ReadEach<LinkPathRoleReads<T, L>, Iv>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Ir>,
{
    const DEADLINE: bool = true;
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<CloseReasonWritten>()
            .add::<LinkPathRoleChanged>()
            .add::<NodeStarted<layer::LinkPath>>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::LinkPath>) -> Option<InstantOf<T>> {
        lineage.get::<LinkPathRole<InstantOf<T>>, I>().end_time()
    }
    fn expire<'v, B: CallBundle>(
        _: LineageOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let NodeKey::LinkPath(path, link) = others.here().clone() else {
            unreachable!("a link path's lend carries its key")
        };
        Some(StructureRequest::EndLinkPath { path, link })
    }
    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let closing = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .is_written();
        if closing {
            match *lineage.get::<LinkPathRole<InstantOf<T>>, I>() {
                LinkPathRole::Candidate => {
                    let NodeKey::LinkPath(path, link) = others.here().clone() else {
                        unreachable!("a link path's lend carries its key")
                    };
                    return Some(StructureRequest::EndLinkPath { path, link });
                }
                LinkPathRole::Active | LinkPathRole::Settling(_) => {
                    let frunk_core::hlist_pat![peer, thresholds, idle] =
                        lineage.read_each::<LinkPathRoleReads<T, L>, Iv>();
                    let pto = current_probe_timeout::<T, L, B, Ima, Ir>(peer, thresholds, others)
                        // with no recovery layer, the last one the idle timeout took
                        .unwrap_or_else(|| idle.probe_timeout());
                    // an end beyond what the instant type represents is
                    // none: the closing period is cut short rather than
                    // kept forever
                    let end = now.checked_add(pto.saturating_mul(3)).unwrap_or(now);
                    let changed = lineage
                        .get_mut::<LinkPathRole<InstantOf<T>>, I>()
                        .close(end);
                    publish_some(&mut lineage, changed);
                }
                LinkPathRole::Closing(_) | LinkPathRole::Draining(_) => {}
            }
        }
        let role = lineage.get::<LinkPathRole<InstantOf<T>>, I>();
        let wanted = *role == LinkPathRole::Active;
        let NodeKey::LinkPath(path, link) = others.here().clone() else {
            unreachable!("a link path's lend carries its key")
        };
        match (wanted, role.has_recovery(), others.has_recovery()) {
            (true, _, false) => Some(StructureRequest::AddRecovery {
                args: layer::RecoveryArgs {
                    path,
                    link,
                    initial_rtt: None,
                },
            }),
            (_, false, true) => Some(StructureRequest::EndRecovery { path, link }),
            _ => None,
        }
    }
}

/// What a link path's role reads to enter `Closing`, besides the record of
/// why the connection closed and the RTT estimates; it subscribes to no
/// event of these.
type LinkPathRoleReads<T, L> = HList![
    PeerTransportParameters<TransportParameterSlots<L>>,
    LossThresholds,
    IdleTimeout<InstantOf<T>>
];
