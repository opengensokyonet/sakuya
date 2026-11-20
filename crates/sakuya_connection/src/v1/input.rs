//! What a logical path receives: the datagram receiver it takes datagrams
//! from, the inputs it holds until their keys come, and the call that takes
//! each of them in.
//!
//! [`logical_path_receiving`] is the first call of each logical path. Whenever
//! it looks for its next input, it first registers to be woken by the
//! logical path's [`StatelessResetSignal`], then looks at it: once routing
//! has marked it, the call writes [`CloseReason::StatelessReset`] into the
//! record of why the connection closed, unless a reason is already there,
//! and puts every link path into `Draining` (RFC 9000 §10.3.1), as a
//! CONNECTION_CLOSE frame from the peer does. It then goes on taking inputs
//! in, which draining link paths drop. It goes through one input at a time:
//!
//! 1. The next input is the first held one, in the order of arrival, that
//!    the keys installed since can process; otherwise the next of the first
//!    datagrams the connection was made with, which the first logical path
//!    owns; otherwise the next delivery of the logical path's datagram
//!    receiver ([`LogicalPathDatagramReceiver`]).
//!    A logical path without a receiver waits until a held input can go.
//!    One poll handles at most
//!    [`max_datagrams_per_poll`](LogicalPathReceivingLimits::max_datagrams_per_poll)
//!    inputs; at the limit the call wakes itself and yields once, so that
//!    the connection's other calls, and other tasks of the executor, are
//!    not held up while the peer keeps sending.
//! 2. A delivery the logical path already owns is taken as it is. A
//!    competing candidate is judged by the first packet of its datagram. A
//!    short header is a 1-RTT packet: before the 1-RTT receive keys this
//!    side waits, holding the candidate; with them, the logical path takes
//!    the datagram when a copy of the packet opens with them, and leaves it
//!    to the other candidates otherwise (RFC 9001 §5.7). A long header is
//!    taken when its Source Connection ID is the one the peer chose for the
//!    handshake, and by a client before a packet from the peer opened
//!    ([`long_header_belongs`]); it is left to the other candidates
//!    otherwise.
//! 3. The anti-amplification limit of the logical link the datagram arrived
//!    over counts the whole datagram before any packet in it is read (RFC
//!    9000 §8.1).
//! 4. The packets are cut from the datagram and received one by one
//!    ([`receive_packet`]), each with its
//!    own copy of the facts of the datagram's arrival. A packet whose keys
//!    have not come is held; a packet whose Destination Connection ID
//!    differs from the first one's is passed over (RFC 9000 §12.2); a
//!    header that tells no boundary ends the datagram. A server passes over
//!    the Initial packets of a datagram whose whole payload is shorter than
//!    [`MIN_DATAGRAM_SIZE`] and receives its other packets (RFC 9000 §14.1). A packet that causes
//!    a connection error writes it into the record of why the connection
//!    closed; the rest of the datagram is dropped, and the call yields, so
//!    that the link paths enter closing before the next input.
//!
//!    A server's 1-RTT packet over a logical link with no link path opens,
//!    and, when it is no duplicate, goes to connection migration
//!    ([`MigrationRules::admit`]) unless the connection is closing: dropped,
//!    the rest of the datagram goes with it; admitted, receiving stops and
//!    the call yields a request to build a `Candidate` link path over the
//!    link, then one to end each link path the migration policy named. Once
//!    the driver made them, the packet goes on, the datagram counts toward
//!    the anti-amplification limit of the new link path's entry, and the
//!    rest of the datagram follows. Each packet processed goes to connection
//!    migration too ([`MigrationRules::processed`]): the local connection ID
//!    strategy hears when the peer switched connection IDs, and the active
//!    link path may switch; receiving stops again for the requests that
//!    follow from it, such as moving a recovery layer, which the call
//!    yields in order before anything else. What the path validations of
//!    the link paths concluded goes to connection migration the same way
//!    ([`MigrationRules::concluded`]): after each packet processed, for
//!    the PATH_RESPONSE frames it carried, and before the next input, for
//!    a validation that gave up at its deadline, which wakes the call. A
//!    failed validation of the active link path with no validated path to
//!    return to closes the connection silently instead, for
//!    [`AbortCause::PathValidationFailed`]: unless a reason is already
//!    written, every link path drains at once and nothing is sent (RFC 9000
//!    §9.3.2); the rest of the datagram is dropped.
//! 5. When the link path the datagram arrived on is still closing once
//!    its packets were received, and its close packet is sealed, the
//!    datagram is one more the close packet may answer: the close packet
//!    counts it, and the link path's planner decides by the count whether
//!    it goes again.
//!
//! The inputs held, packets and candidates alike, are at most
//! [`max_held_inputs`](LogicalPathReceivingLimits::max_held_inputs) for the
//! logical path; past it the input that arrives is dropped. A server
//! drops Retry and Version Negotiation packets; a client receives them as
//! `receive_unprotected` says.
//!
//! [`logical_path_receiving`] is also the operation struct
//! [`LogicalPathReceiving`], with `LogicalPathReceivingExt` on receiver
//! accesses.
// `#[call]` generates a constructor and an extension trait without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use core::{
    fmt,
    future::poll_fn,
    num::NonZeroUsize,
    ops::ControlFlow,
    pin::Pin,
    task::{Context, Poll},
};
use std::{collections::VecDeque, sync::Arc};

use bytes::Bytes;
use frunk_core::{coproduct::CoproductSelector, hlist_pat};
use nitori_call::{LentAccess, LentCall, ReceiverFamily, call};
use nitori_io::SplitTo;
use sakuya_datagram_routing::{
    claim::{
        candidate::{
            DatagramClaimAccess, DatagramClaimAttempt, DatagramClaimCandidate, DatagramClaimOutcome,
        },
        delivery::{DatagramDelivery, ExclusiveDatagramDelivery},
        finish::UnclaimedHandoff,
        lock::DatagramClaimLock,
        queue::{DatagramDeliveryQueue as _, RefCellDatagramDeliveryQueue},
        route_match::DatagramRouteMatchInfo,
    },
    route::{association::MatchAssociation, interpretation::FirstPacketInterpretation},
};
use sakuya_link::{ArrivalFacts, Link, LinkId, MIN_DATAGRAM_SIZE, ReceivedDatagram};
use sakuya_packet_protection_v1::backend::CryptoBackend;
use sakuya_recovery_v1::{
    factory::{LendCongestion, RecoveryFactory},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    receive_journals::{MaxAckRanges, ReceiveJournals},
};
use sakuya_stream_v1::connection::{AbortCause, CloseReason};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength},
    parameters::ParametersOf,
    parts::{CoprodInjector, HList, Selector},
};
use sakuya_wire_v1::{
    encryption_level::EncryptionLevel,
    frame::{FrameType, set::FrameSet},
    packet_number::PacketNumber,
    protected_packet::{IntoPackets, IntoPacketsError, Packet, ProtectedPacket, into_packets},
    role::Role,
    transport_parameters::{
        TransportParameterSlots, TransportParameterSpace, integer::MaxAckDelay,
    },
};

use super::{
    Choices, CloseCauseOf, EventsOf, HostSendStrategyTypes, LinkPathRoleReads, OwnZeroRttKeysOf,
    Side,
    aead_usage::AeadUsage,
    amplification::{AddressValidation, AntiAmplification},
    close::{CloseReasonRecord, LocalCloseCause},
    close_packet::ClosePacket,
    component_events::{
        AmplificationCreditChanged, DestinationConnectionIdsChanged, KeysDiscarded, KeysInstalled,
        PathValidationConcluded, RetryReceived, level,
    },
    connection_ids::{
        ConnectionIdsOf, InitialDestinationConnectionIds, PeerHandshakeConnectionId,
        ResetTokenRegistrarOf,
    },
    dispatch::{drain_each_link_path, drain_link_paths},
    error::{ConnectionError, V1ConnectionErrorOf},
    events::{ConnectionEventSink, ConnectionEvents, PacketEvents, PlainPacket},
    feedback::LineageFeedback,
    first_flight::FirstFlightPacket,
    idle::IdleTimeout,
    key_phase::KeyPhaseNumbers,
    keys::{HandshakeKeys, InitialKeys, OneRttKeys, OneRttReceiveKeys, PacketProtectionBackend},
    link::LinkClone,
    link::LinkFacts,
    long_header_claim::long_header_belongs,
    migration::rules::{MigrationRequest, MigrationRules, PathValidationClose},
    receive::{
        DropReason, LevelReceiveKeys, OpenedPacket, PacketOutcome, ReceivedPacket, destination_of,
        one_rtt_receive_keys, open_one_rtt, packet_number_offset, receive_keys, receive_opened,
        receive_packet, v1_error,
    },
    recovery::RttOf,
    recovery::{CongestionPartOf, OthersOf, RecoveryFactoryOf},
    retry::{
        RestartRecoveryTakes, RetryDecision, check_retry, restart_recovery, retry_initial_keys,
    },
    send::SendTypes,
    send_planning::ComponentPublishing,
    spaces::AckObligationsOf,
    spaces::SendJournalsOf,
    stateless_reset::StatelessResetSignal,
    streams::resets::StreamResetsOf,
    streams::send::StreamIntent,
    version_negotiation::check_version_negotiation,
};
use crate::role::LinkPathRole;
use crate::v1::SendParametersOf;
use crate::v1::StreamSetFamilyOf;
use crate::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    clock::{InstantOf, LinkIdOf},
    component::{ArgsOf, LineageOf, RequestOf},
    component_event::{EventSubscriptions, Happened},
    connection_id::DestinationConnectionIdStrategy,
    dispatch::FrameSetDispatch,
    error::ConnectionErrorsOf,
    feedback::FeedbackSummariesOf,
    frame_source::{EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts},
    layer::{self, LinkPathArgs, LogicalPath, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    share::{FlatMut, LineageLists, LineagePartList, NodeData},
    take::{GetAt, ReadEach, TakeEach},
};

/// A datagram as it arrived over the link `Lk`.
type DatagramOf<Lk> = ReceivedDatagram<<Lk as Link>::Payload, Lk>;

/// What routing gives a receiver of datagrams over the link `Lk`, in a
/// routing domain whose handoff is `H` and whose candidates compete under
/// `C`.
type DeliveryOf<Lk, H, C> = DatagramDelivery<DatagramOf<Lk>, <Lk as Link>::Local, H, C>;

/// A candidate for a datagram over the link `Lk`, in a routing domain whose
/// handoff is `H` and whose candidates compete under `C`.
type CandidateOf<Lk, H, C> = DatagramClaimCandidate<DatagramOf<Lk>, <Lk as Link>::Local, H, C>;

/// The datagram receiver of one logical path: where the deliverers of its
/// route entries put what routing gives them, and where its receiving call
/// takes each delivery from.
///
/// `Lk` is the link datagrams arrive over.
pub trait LogicalPathDatagramReceiver<Lk: Link> {
    /// What takes over a datagram that every candidate left, in the routing
    /// domain the receiver's deliverers serve.
    type Handoff: UnclaimedHandoff<DatagramOf<Lk>>;
    /// The lock the candidates of that routing domain compete under.
    type ClaimLock: DatagramClaimLock;

    /// The next delivery, or `Pending` until there is one; the waker of `cx`
    /// is woken when one comes.
    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<DeliveryOf<Lk, Self::Handoff, Self::ClaimLock>>;
}

/// A delivery queue on one thread is a receiver: its deliverers post to it.
impl<Lk: Link, H: UnclaimedHandoff<DatagramOf<Lk>>, C: DatagramClaimLock>
    LogicalPathDatagramReceiver<Lk>
    for RefCellDatagramDeliveryQueue<DatagramDelivery<DatagramOf<Lk>, Lk::Local, H, C>>
{
    type Handoff = H;
    type ClaimLock = C;

    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramDelivery<DatagramOf<Lk>, Lk::Local, H, C>> {
        self.poll_recv(cx)
    }
}

/// An input a logical path holds until the keys to process it come.
///
/// `Lk` is the link datagrams arrive over, `H` the handoff of the routing
/// domain and `C` the lock its candidates compete under.
// most held inputs are packets: boxing them would allocate for each
#[allow(clippy::large_enum_variant)]
pub enum HeldInput<Lk: Link, H: UnclaimedHandoff<DatagramOf<Lk>>, C: DatagramClaimLock> {
    /// A packet cut from a datagram this logical path took, whose level has
    /// no receive keys yet: a 0-RTT packet before a server decided on
    /// 0-RTT, a Handshake packet before the Handshake keys, a 1-RTT packet
    /// before the 1-RTT receive keys.
    Packet(ReceivedPacket<Lk::Payload, Lk>),
    /// A competing candidate whose first packet is a 1-RTT packet, which
    /// waits for the 1-RTT receive keys to be judged.
    Candidate(DatagramClaimCandidate<DatagramOf<Lk>, Lk::Local, H, C>),
}

impl<Lk: Link, H: UnclaimedHandoff<DatagramOf<Lk>>, C: DatagramClaimLock> HeldInput<Lk, H, C> {
    /// Whether the input can go on: the level it waits for is no longer
    /// waited for.
    fn released(&self, levels: ReceivableLevels) -> bool {
        match self {
            Self::Packet(packet) => levels.at(packet.packet().level()),
            // the first packet of a held candidate is a 1-RTT packet
            Self::Candidate(_) => levels.at(EncryptionLevel::OneRtt),
        }
    }
}

/// For each encryption level, whether its packets are no longer waited
/// for: the receive keys have come, or none are to come.
#[derive(Debug, Clone, Copy)]
struct ReceivableLevels {
    initial: bool,
    zero_rtt: bool,
    handshake: bool,
    one_rtt: bool,
}

impl ReceivableLevels {
    /// The levels as the keys in `lineage` stand now.
    fn of<T, L, Ii, Ih, Io, Iz>(lineage: &LineageOf<'_, T, L, LogicalPath>) -> Self
    where
        T: Choices,
        L: LineagePartList<T>,
        for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialKeys<T::Crypto>, Ii>
            + GetAt<HandshakeKeys<T::Crypto>, Ih>
            + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
            + GetAt<OwnZeroRttKeysOf<T>, Iz>,
    {
        let receivable = |level| {
            !matches!(
                receive_keys::<T, L, Ii, Ih, Io, Iz>(lineage, level),
                LevelReceiveKeys::NotYet
            )
        };
        Self {
            initial: receivable(EncryptionLevel::Initial),
            zero_rtt: receivable(EncryptionLevel::ZeroRtt),
            handshake: receivable(EncryptionLevel::Handshake),
            one_rtt: receivable(EncryptionLevel::OneRtt),
        }
    }

    /// Whether the packets of `level` are no longer waited for.
    fn at(self, level: EncryptionLevel) -> bool {
        match level {
            EncryptionLevel::Initial => self.initial,
            EncryptionLevel::ZeroRtt => self.zero_rtt,
            EncryptionLevel::Handshake => self.handshake,
            EncryptionLevel::OneRtt => self.one_rtt,
        }
    }
}

impl<Lk, H, C> fmt::Debug for HeldInput<Lk, H, C>
where
    Lk: Link + fmt::Debug,
    Lk::Payload: fmt::Debug,
    Lk::Local: fmt::Debug,
    Lk::Instant: fmt::Debug,
    H: UnclaimedHandoff<DatagramOf<Lk>>,
    C: DatagramClaimLock,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(packet) => f.debug_tuple("Packet").field(packet).finish(),
            Self::Candidate(candidate) => f.debug_tuple("Candidate").field(candidate).finish(),
        }
    }
}

/// The datagram receiver of a connection's initial path, given when the
/// connection is made and taken by the first logical path built.
pub struct InitialPathReceiver<R>(Option<R>);

impl<R> InitialPathReceiver<R> {
    /// The receiver `receiver`, for the connection's initial path.
    pub fn new(receiver: R) -> Self {
        Self(Some(receiver))
    }

    /// Move the receiver out into a new value, leaving this one empty.
    pub(crate) fn moved(&mut self) -> Self {
        Self(self.0.take())
    }

    /// The receiver, the first time it is asked for; `None` afterwards.
    pub(crate) fn take(&mut self) -> Option<R> {
        self.0.take()
    }
}

impl<R> fmt::Debug for InitialPathReceiver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialPathReceiver")
            .field("taken", &self.0.is_none())
            .finish_non_exhaustive()
    }
}

/// The limits of the receiving call of every logical path of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogicalPathReceivingLimits {
    /// How many inputs, datagrams and held inputs released, one poll of the
    /// call handles at most before it yields.
    pub max_datagrams_per_poll: NonZeroUsize,
    /// How many inputs a logical path holds at most until their keys come.
    pub max_held_inputs: usize,
}

/// What a logical path receives: its datagram receiver, if it has one, the
/// datagrams it receives before what the receiver delivers, and the inputs
/// it holds until their keys come, in the order of arrival.
///
/// `Lk` is the link datagrams arrive over, `R` the receiver.
pub struct LogicalPathInput<Lk: Link, R: LogicalPathDatagramReceiver<Lk>> {
    receiver: Option<R>,
    /// The first datagrams not read yet, and the length of a short
    /// header's Destination Connection ID they are cut with.
    first: VecDeque<DatagramOf<Lk>>,
    first_dcid_len: ConnectionIdLength,
    /// The Initial packets read with the first flight before the
    /// connection was made, which the connection's events hear of when the
    /// receiving call first looks for an input.
    first_read: Vec<FirstFlightPacket<Lk::Instant>>,
    held: VecDeque<HeldInput<Lk, R::Handoff, R::ClaimLock>>,
    limits: LogicalPathReceivingLimits,
    /// The inputs handled in this poll of the receiving call.
    handled: usize,
    /// The changes of structure asked for and not handed to the driver
    /// yet, in order.
    requests: VecDeque<ReceiveRequest<Lk>>,
    /// The datagram whose receiving stopped for them, to go on with once
    /// they are made.
    stopped: Option<StoppedDatagram<Lk>>,
}

/// A change of structure the receiving call asks for.
enum ReceiveRequest<Lk: Link> {
    /// A `Candidate` link path over the link a packet arrived over.
    AddLinkPath {
        /// The connection's clone of the link.
        link: Lk,
        /// Whether the packet is sent to another of this side's connection
        /// IDs than the peer last used on the active link path.
        peer_switched_local_id: bool,
    },
    /// What connection migration asks for.
    Migration(MigrationRequest<LinkId<Lk::Local, Lk::Peer>>),
}

impl<Lk: Link> ReceiveRequest<Lk> {
    /// The request of the tree's structure, for the logical path `path`.
    fn into_structure<K>(self, path: K) -> StructureRequest<K, Lk> {
        match self {
            Self::AddLinkPath {
                link,
                peer_switched_local_id,
            } => StructureRequest::AddLinkPath {
                args: LinkPathArgs {
                    path,
                    link,
                    role: LinkPathRole::Candidate,
                    peer_switched_local_id,
                },
            },
            Self::Migration(request) => request.into_structure(path),
        }
    }
}

/// A datagram whose receiving stopped for a change of structure: the packet
/// that waits for its link path, if one does, the packets after it, the
/// facts of its arrival, its size and whether it was counted toward the
/// anti-amplification limit of its logical link.
struct StoppedDatagram<Lk: Link> {
    opened: Option<OpenedPacket<Lk>>,
    packets: IntoPackets<Lk::Payload>,
    arrival: ArrivalFacts<Lk>,
    size: usize,
    counted: bool,
}

impl<Lk: Link, R: LogicalPathDatagramReceiver<Lk>> LogicalPathInput<Lk, R> {
    /// The input of a logical path that takes datagrams from `receiver`, if
    /// any, within `limits`, and holds nothing yet.
    pub fn new(receiver: Option<R>, limits: LogicalPathReceivingLimits) -> Self {
        Self {
            receiver,
            first: VecDeque::new(),
            first_dcid_len: ConnectionIdLength::ZERO,
            first_read: Vec::new(),
            held: VecDeque::new(),
            limits,
            handled: 0,
            requests: VecDeque::new(),
            stopped: None,
        }
    }

    /// Receive `datagrams`, which the logical path owns, before anything
    /// the receiver delivers, cutting them with `dcid_len` as the length of
    /// a short header's Destination Connection ID; hold `held`, as far as
    /// the limit allows; and give the connection's events `read`, the
    /// Initial packets read with the first flight, first.
    pub(super) fn start_with(
        &mut self,
        datagrams: Vec<DatagramOf<Lk>>,
        dcid_len: ConnectionIdLength,
        held: Vec<HeldInput<Lk, R::Handoff, R::ClaimLock>>,
        read: Vec<FirstFlightPacket<Lk::Instant>>,
    ) {
        self.first.extend(datagrams);
        self.first_dcid_len = dcid_len;
        self.first_read = read;
        for input in held {
            self.hold(input);
        }
    }

    /// The limits the logical path receives within.
    pub fn limits(&self) -> LogicalPathReceivingLimits {
        self.limits
    }

    /// How many inputs are held.
    pub fn held_len(&self) -> usize {
        self.held.len()
    }

    /// The inputs held, in the order of arrival.
    pub fn held(&self) -> impl Iterator<Item = &HeldInput<Lk, R::Handoff, R::ClaimLock>> {
        self.held.iter()
    }

    /// Hold `input`, unless as many inputs as the limit allows are held
    /// already: then it is dropped.
    fn hold(&mut self, input: HeldInput<Lk, R::Handoff, R::ClaimLock>) {
        if self.held.len() < self.limits.max_held_inputs {
            self.held.push_back(input);
        }
    }

    /// The first held input, in the order of arrival, that `levels`
    /// release. Once the last one is released, the hold lets its room go:
    /// inputs are held only while the handshake's keys come.
    fn release(
        &mut self,
        levels: ReceivableLevels,
    ) -> Option<HeldInput<Lk, R::Handoff, R::ClaimLock>> {
        let at = self.held.iter().position(|input| input.released(levels))?;
        let input = self.held.remove(at);
        if self.held.is_empty() {
            self.held = VecDeque::new();
        }
        input
    }

    /// Whether this poll has handled as many inputs as it may; if so, the
    /// count starts again for the next poll.
    fn yield_due(&mut self) -> bool {
        let due = self.handled >= self.limits.max_datagrams_per_poll.get();
        if due {
            self.handled = 0;
        }
        due
    }

    /// Use up this poll's inputs, so that the call yields before the next.
    fn use_up(&mut self) {
        self.handled = self.limits.max_datagrams_per_poll.get();
    }

    /// Whether a change of structure waits to be handed to the driver, or
    /// a datagram stopped for one.
    fn stopped(&self) -> bool {
        !self.requests.is_empty() || self.stopped.is_some()
    }
}

impl<Lk: Link, R: LogicalPathDatagramReceiver<Lk>> fmt::Debug for LogicalPathInput<Lk, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogicalPathInput")
            .field("receiver", &self.receiver.is_some())
            .field("first", &self.first.len())
            .field("held", &self.held.len())
            .finish_non_exhaustive()
    }
}

/// What the receiving call of a logical path does with its view: everything
/// but waiting.
pub trait LogicalPathReceivingCapability: ReceiverFamily {
    /// The link datagrams arrive over.
    type Link: Link;
    /// The handoff of the routing domain.
    type Handoff: UnclaimedHandoff<DatagramOf<Self::Link>>;
    /// The lock the candidates of the routing domain compete under.
    type ClaimLock: DatagramClaimLock;
    /// A request of the connection's structure.
    type Request;

    /// The next input to judge or take, after draining the link paths if a
    /// stateless reset was received and receiving the held packets that
    /// were released; `Pending` at the limit of a poll, having woken the
    /// call, or until a delivery or a stateless reset comes. `None` when
    /// receiving stopped for a change of structure, which
    /// [`next_request`](Self::next_request) gives.
    #[allow(clippy::type_complexity)] // the delivery of the routing crate
    fn poll_next_input<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
    ) -> Poll<
        Option<
            DatagramDelivery<
                DatagramOf<Self::Link>,
                <Self::Link as Link>::Local,
                Self::Handoff,
                Self::ClaimLock,
            >,
        >,
    >
    where
        Self: 'v;

    /// The next change of structure receiving asks for, going on with the
    /// datagram that stopped for the ones before once they are made; `None`
    /// once nothing waits.
    fn next_request<'v>(view: Pin<&mut Self::ReceiverView<'v>>) -> Option<Self::Request>
    where
        Self: 'v;

    /// Judge whether the logical path takes the datagram of a competing
    /// candidate, by its first packet.
    fn judge<'v, 'access>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        access: DatagramClaimAccess<'access, DatagramOf<Self::Link>>,
        route: &DatagramRouteMatchInfo<<Self::Link as Link>::Local>,
    ) -> DatagramClaimOutcome<'access, (), (), DatagramOf<Self::Link>>
    where
        Self: 'v;

    /// Hold a candidate whose judgment waits for keys.
    fn hold_candidate<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        candidate: CandidateOf<Self::Link, Self::Handoff, Self::ClaimLock>,
    ) where
        Self: 'v;

    /// Receive a datagram the logical path owns: count it, cut it into
    /// packets and receive each.
    fn receive_datagram<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        delivery: ExclusiveDatagramDelivery<DatagramOf<Self::Link>, <Self::Link as Link>::Local>,
    ) where
        Self: 'v;
}

/// The positions the receiving call takes by: `Ip` of its input and `Ic` of
/// the record of why the connection closed in the logical path's lineage;
/// those of [`receive_packet`]; `Ian` of
/// the anti-amplification limit in the entry of a logical link; those it
/// drains the link paths by when a stateless reset was received: `Is` of
/// the logical path's [`StatelessResetSignal`], and those of
/// [`drain_link_paths`]; and `Icp` and `Ipl` of a link path's close packet,
/// to read and to count a datagram in; and
/// those a client receives a Retry by ([`receive_unprotected`]).
type Positions<
    Ip,
    Ic,
    Ii,
    Ih,
    Io,
    Iz,
    Ij,
    Im,
    Ia,
    It,
    Iu,
    Ikp,
    Ir,
    Ie,
    Ik,
    Hd,
    Ian,
    Icid,
    Iph,
    Iev,
    Icp,
    Ipl,
    Is,
    Iv,
    Ima,
    Irt,
    Il,
    Iid,
    Ibk,
    Iw,
    Isj,
    If,
    Ile,
    Ikr,
    Hf,
    Ies,
    S,
    Ls,
    Hm,
> = (
    (Ip, Ic),
    (Ii, Ih, Io, Iz, Ij, Im, Ia, It, Iu, Ikp, Icid, Iph, Iev),
    (Ir, Ie, Ik, Hd),
    Ian,
    (Is, Iv, Ima, Irt, Il),
    (Icp, Ipl),
    ((Iid, Ibk, Iw), (Isj, If, Ile, Ikr, Hf, Ies), (S, Ls)),
    Hm,
);

impl<
    T,
    L,
    K,
    B,
    Ip,
    Ic,
    Ii,
    Ih,
    Io,
    Iz,
    Ij,
    Im,
    Ia,
    It,
    Iu,
    Ikp,
    Ir,
    Ie,
    Ik,
    Hd,
    Ian,
    Icid,
    Iph,
    Iev,
    Icp,
    Ipl,
    Is,
    Iv,
    Ima,
    Irt,
    Il,
    Iid,
    Ibk,
    Iw,
    Isj,
    If,
    Ile,
    Ikr,
    Hf,
    Ies,
    S,
    Ls,
    Hm,
> LogicalPathReceivingCapability
    for NodeCallFamily<
        T,
        L,
        LogicalPath,
        K,
        Positions<
            Ip,
            Ic,
            Ii,
            Ih,
            Io,
            Iz,
            Ij,
            Im,
            Ia,
            It,
            Iu,
            Ikp,
            Ir,
            Ie,
            Ik,
            Hd,
            Ian,
            Icid,
            Iph,
            Iev,
            Icp,
            Ipl,
            Is,
            Iv,
            Ima,
            Irt,
            Il,
            Iid,
            Ibk,
            Iw,
            Isj,
            If,
            Ile,
            Ikr,
            Hf,
            Ies,
            S,
            Ls,
            Hm,
        >,
        B,
    >
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd> + StreamResetsOf,
    L: FeedbackSummariesOf + EstablishedSourceComponentsOf<T, L>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    L: MigrationRules<T, Hm>,
    S: 'static,
    Ls: 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ibk>
        + GetAt<<T::Side as Side>::Own, Iw>
        + GetAt<SendJournalsOf<T, L>, Isj>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ile>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, RestartRecoveryTakes<T, L, S, Ls>, Ikr>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Ies>,
    B: CallBundle,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LogicalPathInput<T::Link, T::Receiver>, Ip>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<OwnZeroRttKeysOf<T>, Iz>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<ClosePacket, Icp> + TakeEach<'s, HList![ClosePacket], Ipl>,
    SendTypes<T, L>: HostSendStrategyTypes,
    L: ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        GetAt<Arc<StatelessResetSignal>, Is> + ReadEach<LinkPathRoleReads<T, L>, Iv>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
{
    type Link = T::Link;
    type Handoff = <T::Receiver as LogicalPathDatagramReceiver<T::Link>>::Handoff;
    type ClaimLock = <T::Receiver as LogicalPathDatagramReceiver<T::Link>>::ClaimLock;
    type Request = RequestOf<T, L>;

    fn poll_next_input<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        cx: &mut Context<'_>,
    ) -> Poll<
        Option<
            DatagramDelivery<
                DatagramOf<T::Link>,
                <T::Link as Link>::Local,
                Self::Handoff,
                Self::ClaimLock,
            >,
        >,
    >
    where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        if <EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED {
            let read = core::mem::take(
                &mut lineage
                    .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
                    .first_read,
            );
            first_flight_received::<T, L, Iev>(lineage, read);
        }
        drain_on_stateless_reset::<T, L, B, Ic, Ir, Is, Iv, Ima, Irt, Il>(lineage, others, cx);
        // what path validation concluded since, by a deadline, is acted on
        // first
        let mut requests = Vec::new();
        let now = others.now();
        match <L as MigrationRules<T, Hm>>::concluded(lineage, others, now, &mut requests) {
            None => {
                if !requests.is_empty() {
                    lineage
                        .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
                        .requests
                        .extend(requests.into_iter().map(ReceiveRequest::Migration));
                }
            }
            Some(close) => {
                close_on_failed_validation::<T, L, B, Ic, Il, Ie>(lineage, others, close, now);
            }
        }
        loop {
            let levels = ReceivableLevels::of::<T, L, Ii, Ih, Io, Iz>(lineage);
            let mut input = lineage.get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>();
            if input.stopped() {
                return Poll::Ready(None);
            }
            if input.yield_due() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(held) = input.release(levels) {
                input.handled += 1;
                match held {
                    HeldInput::Candidate(candidate) => {
                        return Poll::Ready(Some(DatagramDelivery::Competing(candidate)));
                    }
                    HeldInput::Packet(packet) => {
                        // a connection error has used up the poll, and the
                        // check above yields; a held packet arrived before the
                        // handshake completed, when no link path is built
                        let _ = receive_one::<
                            T,
                            L,
                            B,
                            Ip,
                            Ic,
                            Ii,
                            Ih,
                            Io,
                            Iz,
                            Ij,
                            Im,
                            Ia,
                            It,
                            Iu,
                            Ikp,
                            Ir,
                            Ie,
                            Ik,
                            Hd,
                            Icid,
                            Iph,
                            Iev,
                            Hm,
                            Il,
                        >(
                            lineage, others, ReceiveInput::Packet(packet), false
                        );
                        continue;
                    }
                }
            }
            if let Some(datagram) = input.first.pop_front() {
                input.handled += 1;
                let dcid_len = input.first_dcid_len;
                receive_owned::<
                    T,
                    L,
                    B,
                    Ip,
                    Ic,
                    Ii,
                    Ih,
                    Io,
                    Iz,
                    Ij,
                    Im,
                    Ia,
                    It,
                    Iu,
                    Ikp,
                    Ir,
                    Ie,
                    Ik,
                    Hd,
                    Ian,
                    Icid,
                    Iph,
                    Iev,
                    Icp,
                    Ipl,
                    Il,
                    Iid,
                    Ibk,
                    Iw,
                    Isj,
                    If,
                    Ile,
                    Ikr,
                    Hf,
                    Ies,
                    S,
                    Ls,
                    Hm,
                >(lineage, others, datagram, dcid_len);
                continue;
            }
            let Some(receiver) = input.receiver.as_mut() else {
                input.handled = 0;
                return Poll::Pending;
            };
            return match receiver.poll_next(cx) {
                Poll::Ready(delivery) => {
                    input.handled += 1;
                    Poll::Ready(Some(delivery))
                }
                Poll::Pending => {
                    input.handled = 0;
                    Poll::Pending
                }
            };
        }
    }

    fn next_request<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
    ) -> Option<RequestOf<T, L>>
    where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let NodeKey::LogicalPath(path) = others.here().clone() else {
            unreachable!("a logical path's lend carries its key")
        };
        loop {
            let stopped = {
                let mut input = lineage.get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>();
                if let Some(request) = input.requests.pop_front() {
                    return Some(request.into_structure(path));
                }
                input.stopped.take()?
            };
            receive_rest::<
                T,
                L,
                B,
                Ip,
                Ic,
                Ii,
                Ih,
                Io,
                Iz,
                Ij,
                Im,
                Ia,
                It,
                Iu,
                Ikp,
                Ir,
                Ie,
                Ik,
                Hd,
                Ian,
                Icid,
                Iph,
                Iev,
                Icp,
                Ipl,
                Il,
                Iid,
                Ibk,
                Iw,
                Isj,
                If,
                Ile,
                Ikr,
                Hf,
                Ies,
                S,
                Ls,
                Hm,
            >(lineage, others, stopped);
        }
    }

    fn judge<'v, 'access>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        access: DatagramClaimAccess<'access, DatagramOf<T::Link>>,
        route: &DatagramRouteMatchInfo<<T::Link as Link>::Local>,
    ) -> DatagramClaimOutcome<'access, (), (), DatagramOf<T::Link>>
    where
        Self: 'v,
    {
        let lineage = &view.get_mut().lineage;
        let FirstPacketInterpretation::Short { dcid_len } = route.interpretation() else {
            let peer = lineage.get::<PeerHandshakeConnectionId, Iph>().get();
            return if long_header_belongs(access.bytes(), peer.as_ref(), <T::Side as Side>::ROLE) {
                DatagramClaimOutcome::Claimed(access.into_exclusive(), ())
            } else {
                DatagramClaimOutcome::Abandoned(())
            };
        };
        let keys = match one_rtt_receive_keys::<T, L, Io>(lineage) {
            LevelReceiveKeys::Ready(keys) => keys,
            LevelReceiveKeys::NotYet => return DatagramClaimOutcome::Unclaimed(access),
            LevelReceiveKeys::Gone => return DatagramClaimOutcome::Abandoned(()),
        };
        let largest = lineage
            .get::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>()
            .get(PacketNumberSpaceKind::ApplicationData)
            .and_then(|journals| journals.largest())
            .map(|(number, _)| number);
        let lowest = lineage
            .get::<KeyPhaseNumbers, Ikp>()
            .lowest_received(keys.current().generation());
        if first_packet_opens(keys, lowest, access.bytes(), dcid_len, largest) {
            DatagramClaimOutcome::Claimed(access.into_exclusive(), ())
        } else {
            DatagramClaimOutcome::Abandoned(())
        }
    }

    fn hold_candidate<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        candidate: CandidateOf<T::Link, Self::Handoff, Self::ClaimLock>,
    ) where
        Self: 'v,
    {
        view.get_mut()
            .lineage
            .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
            .hold(HeldInput::Candidate(candidate));
    }

    fn receive_datagram<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        delivery: ExclusiveDatagramDelivery<DatagramOf<T::Link>, <T::Link as Link>::Local>,
    ) where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let (datagram, route) = delivery.consume();
        receive_owned::<
            T,
            L,
            B,
            Ip,
            Ic,
            Ii,
            Ih,
            Io,
            Iz,
            Ij,
            Im,
            Ia,
            It,
            Iu,
            Ikp,
            Ir,
            Ie,
            Ik,
            Hd,
            Ian,
            Icid,
            Iph,
            Iev,
            Icp,
            Ipl,
            Il,
            Iid,
            Ibk,
            Iw,
            Isj,
            If,
            Ile,
            Ikr,
            Hf,
            Ies,
            S,
            Ls,
            Hm,
        >(
            lineage,
            others,
            datagram.into_inner(),
            short_dcid_len(&route),
        );
    }
}

/// Receive `datagram`, which the logical path of `lineage` owns: count it
/// toward the anti-amplification limit of the logical link it arrived
/// over, cut it into packets, a short header's Destination Connection ID
/// being `dcid_len` long, and receive each, until one causes a connection
/// error.
#[allow(clippy::type_complexity)] // the positions of what it takes
fn receive_owned<
    'v,
    T,
    L,
    B,
    Ip,
    Ic,
    Ii,
    Ih,
    Io,
    Iz,
    Ij,
    Im,
    Ia,
    It,
    Iu,
    Ikp,
    Ir,
    Ie,
    Ik,
    Hd,
    Ian,
    Icid,
    Iph,
    Iev,
    Icp,
    Ipl,
    Il,
    Iid,
    Ibk,
    Iw,
    Isj,
    If,
    Ile,
    Ikr,
    Hf,
    Ies,
    S,
    Ls,
    Hm,
>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    datagram: DatagramOf<T::Link>,
    dcid_len: ConnectionIdLength,
) where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd> + StreamResetsOf,
    L: FeedbackSummariesOf + EstablishedSourceComponentsOf<T, L>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    L: MigrationRules<T, Hm>,
    S: 'static,
    Ls: 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ibk>
        + GetAt<<T::Side as Side>::Own, Iw>
        + GetAt<SendJournalsOf<T, L>, Isj>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ile>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, RestartRecoveryTakes<T, L, S, Ls>, Ikr>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Ies>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
    B: CallBundle,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LogicalPathInput<T::Link, T::Receiver>, Ip>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<OwnZeroRttKeysOf<T>, Iz>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<ClosePacket, Icp> + TakeEach<'s, HList![ClosePacket], Ipl>,
    SendTypes<T, L>: HostSendStrategyTypes,
{
    let size = datagram.payload().as_ref().len();
    let link = datagram.link().id().clone();
    // the entry of a logical link no link path is over yet does not
    // exist; there is nothing to count until one is built for it
    let counted = count_received::<T, L, B, Ian>(others, &link, size);
    let (payload, arrival) = datagram.into_parts();
    let datagram = StoppedDatagram {
        opened: None,
        packets: into_packets(payload, dcid_len),
        arrival,
        size,
        counted,
    };
    receive_rest::<
        T,
        L,
        B,
        Ip,
        Ic,
        Ii,
        Ih,
        Io,
        Iz,
        Ij,
        Im,
        Ia,
        It,
        Iu,
        Ikp,
        Ir,
        Ie,
        Ik,
        Hd,
        Ian,
        Icid,
        Iph,
        Iev,
        Icp,
        Ipl,
        Il,
        Iid,
        Ibk,
        Iw,
        Isj,
        If,
        Ile,
        Ikr,
        Hf,
        Ies,
        S,
        Ls,
        Hm,
    >(lineage, others, datagram);
}

/// Receive the packets of `datagram` from where its receiving stopped, as
/// [`receive_owned`] says: first the packet that waited for its link path,
/// if one did, which counts the datagram toward the anti-amplification
/// limit of the entry built with the link path when it was not counted yet.
/// A packet over a logical link with no link path goes to the migration
/// rules ([`MigrationRules::admit`]): the datagram's packets are dropped
/// when the policy admits none, and otherwise receiving stops with the
/// requests of the new link path and of those to end first. A packet
/// processed goes to the migration rules too ([`MigrationRules::processed`])
/// and receiving stops when they ask for a change of structure. A datagram
/// that stopped waits in the logical path's input until the receiving call
/// handed its requests to the driver.
#[allow(clippy::type_complexity)] // the positions of what it takes
fn receive_rest<
    'v,
    T,
    L,
    B,
    Ip,
    Ic,
    Ii,
    Ih,
    Io,
    Iz,
    Ij,
    Im,
    Ia,
    It,
    Iu,
    Ikp,
    Ir,
    Ie,
    Ik,
    Hd,
    Ian,
    Icid,
    Iph,
    Iev,
    Icp,
    Ipl,
    Il,
    Iid,
    Ibk,
    Iw,
    Isj,
    If,
    Ile,
    Ikr,
    Hf,
    Ies,
    S,
    Ls,
    Hm,
>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    mut datagram: StoppedDatagram<T::Link>,
) where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd> + StreamResetsOf,
    L: FeedbackSummariesOf + EstablishedSourceComponentsOf<T, L>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    L: MigrationRules<T, Hm>,
    S: 'static,
    Ls: 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ibk>
        + GetAt<<T::Side as Side>::Own, Iw>
        + GetAt<SendJournalsOf<T, L>, Isj>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ile>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, RestartRecoveryTakes<T, L, S, Ls>, Ikr>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Ies>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
    B: CallBundle,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LogicalPathInput<T::Link, T::Receiver>, Ip>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<OwnZeroRttKeysOf<T>, Iz>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<ClosePacket, Icp> + TakeEach<'s, HList![ClosePacket], Ipl>,
    SendTypes<T, L>: HostSendStrategyTypes,
{
    // a server takes no Initial packet from a datagram too short to
    // have carried a client's first flight (RFC 9000 §14.1)
    let initial_allowed =
        <T::Side as Side>::ROLE == Role::Client || datagram.size >= MIN_DATAGRAM_SIZE;
    let link = datagram.arrival.link().id().clone();
    loop {
        let input = if let Some(opened) = datagram.opened.take() {
            // the link path it waited for is built: the datagram counts
            // toward its entry's limit, once
            if !datagram.counted {
                datagram.counted = count_received::<T, L, B, Ian>(others, &link, datagram.size);
            }
            ReceiveInput::Opened(opened)
        } else {
            let Some(packet) = datagram.packets.next() else {
                break;
            };
            match packet {
                Ok(Packet::Protected(ProtectedPacket::Initial(..))) if !initial_allowed => continue,
                Ok(Packet::Protected(packet)) => {
                    ReceiveInput::Packet(ReceivedPacket::new(packet, datagram.arrival.clone()))
                }
                Ok(packet @ (Packet::Retry(..) | Packet::VersionNegotiation(..))) => {
                    if <T::Side as Side>::ROLE == Role::Client
                        && receive_unprotected::<
                            T,
                            L,
                            B,
                            Ic,
                            Ii,
                            Icid,
                            Iph,
                            Iev,
                            Il,
                            Iid,
                            Ibk,
                            Iw,
                            Isj,
                            If,
                            Ile,
                            Ikr,
                            Hf,
                            Ies,
                            S,
                            Ls,
                        >(lineage, others, packet, &link)
                        .is_break()
                    {
                        break;
                    }
                    continue;
                }
                Err(IntoPacketsError::DcidDiffersFromFirst) => continue,
                Err(IntoPacketsError::UnreadableBoundary { .. }) => break,
            }
        };
        let received = receive_one::<
            T,
            L,
            B,
            Ip,
            Ic,
            Ii,
            Ih,
            Io,
            Iz,
            Ij,
            Im,
            Ia,
            It,
            Iu,
            Ikp,
            Ir,
            Ie,
            Ik,
            Hd,
            Icid,
            Iph,
            Iev,
            Hm,
            Il,
        >(lineage, others, input, true);
        match received {
            Received::Next => {}
            Received::Break => break,
            Received::Stopped => {
                lineage
                    .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
                    .stopped = Some(datagram);
                return;
            }
            Received::AwaitingLinkPath(opened) => {
                let at = opened.arrival().at();
                // at a local end the active link path moved away from, a
                // packet the migration policy drops builds nothing
                if !<L as MigrationRules<T, Hm>>::opened(
                    lineage,
                    others,
                    &link,
                    opened.number().get(),
                ) {
                    dropped::<T, L, Iev>(
                        lineage,
                        at,
                        EncryptionLevel::OneRtt,
                        &DropReason::OldLocalAddress,
                    );
                    return;
                }
                let Some(admitted) = <L as MigrationRules<T, Hm>>::admit(
                    lineage,
                    others,
                    &link,
                    &opened.destination(),
                    at,
                ) else {
                    // the rest of the datagram is the connection's too, and
                    // dropped with it
                    dropped::<T, L, Iev>(
                        lineage,
                        at,
                        EncryptionLevel::OneRtt,
                        &DropReason::LinkPathNotAdmitted,
                    );
                    return;
                };
                let mut input = lineage.get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>();
                input.requests.push_back(ReceiveRequest::AddLinkPath {
                    link: datagram.arrival.link().clone(),
                    peer_switched_local_id: admitted.peer_switched_local_id,
                });
                input.requests.extend(
                    admitted.end.into_iter().map(|link| {
                        ReceiveRequest::Migration(MigrationRequest::EndLinkPath { link })
                    }),
                );
                datagram.opened = Some(opened);
                input.stopped = Some(datagram);
                return;
            }
        }
    }
    validate_by_handshake::<T, L, B, Ii, Ian>(lineage, others, &link);
    close_packet_received::<T, L, B, Ir, Icp, Ipl>(others, &link);
}

/// Count a datagram of `size` bytes, arrived over `link`, toward the
/// anti-amplification limit of the logical link's entry, waking what waits
/// on the limit while the address is not validated; `false` when there is
/// no entry yet, and nothing is counted.
fn count_received<T, L, B, Ian>(
    others: &mut OtherNodes<'_, T, L, B>,
    link: &LinkIdOf<T>,
    size: usize,
) -> bool
where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
{
    let credit_changed = {
        let Some(hlist_pat![mut limit, facts]) =
            others.link_entry::<HList![AntiAmplification, LinkFacts], Ian>(link)
        else {
            return false;
        };
        limit.received(size);
        // the credit counts only while the address is not validated
        facts.validation == AddressValidation::NotValidated
    };
    if credit_changed {
        others.publish_at(
            &NodeKey::LinkEntry(link.clone()),
            Happened::<AmplificationCreditChanged>::new(),
        );
    }
    true
}
/// Receive, as a client, the Retry or Version Negotiation packet `packet`,
/// which arrived over `link`; `Break` when it ends the connection
/// attempt, and the rest of the datagram is dropped.
///
/// Each is checked first ([`check_retry`], [`check_version_negotiation`]),
/// and one to drop is dropped. A valid Version Negotiation packet ends the
/// attempt for [`CloseReason::VersionNegotiation`], with the versions the
/// server listed. A valid Retry goes to the Retry policy, through the side
/// ([`Side::on_retry`]), with how long ago the first Initial packet was
/// sent; giving up ends the attempt for [`CloseReason::RetryAbandoned`].
/// Going on, the recovery state of the link path starts over
/// ([`restart_recovery`]), so that the ClientHello is sent again; the
/// Initial keys are derived from the Retry's Source Connection ID, which
/// the destination connection ID strategy sends to from now on and the
/// connection node keeps as the Retry's
/// ([`InitialDestinationConnectionIds`]); and the side keeps the token
/// for every later Initial packet (RFC 9000 §17.2.5). An attempt that ends
/// sends nothing: every link path drains at once, and the connection ends
/// as at an idle timeout.
///
/// A packet from the server was processed once one opened, the first
/// setting the [`PeerHandshakeConnectionId`], or a Retry was gone on
/// after; a Version Negotiation packet that ends the attempt leaves no
/// later packet to see.
///
/// The positions: `Iid` of the Destination Connection IDs of the first
/// Initial packets, `Ibk` of the backend of packet protection and `Iw` of
/// the side's own data in the logical path's lineage; `Il` of a link
/// path's role; and those of [`restart_recovery`].
#[allow(clippy::type_complexity)] // the positions of what it takes
fn receive_unprotected<
    'v,
    T,
    L,
    B,
    Ic,
    Ii,
    Icid,
    Iph,
    Iev,
    Il,
    Iid,
    Ibk,
    Iw,
    Isj,
    If,
    Ile,
    Ikr,
    Hf,
    Ies,
    S,
    Ls,
>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    packet: Packet<<T::Link as Link>::Payload>,
    link: &LinkIdOf<T>,
) -> ControlFlow<()>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    B: CallBundle,
    <T::Link as Link>::Payload: AsRef<[u8]>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    L: FeedbackSummariesOf + EstablishedSourceComponentsOf<T, L>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    S: 'static,
    Ls: 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ibk>
        + GetAt<<T::Side as Side>::Own, Iw>
        + GetAt<SendJournalsOf<T, L>, Isj>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ile>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, RestartRecoveryTakes<T, L, S, Ls>, Ikr>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Ies>,
{
    let ids = *lineage.get::<InitialDestinationConnectionIds, Iid>();
    let answered = lineage
        .get::<PeerHandshakeConnectionId, Iph>()
        .get()
        .is_some()
        || ids.retry_source().is_some();
    let reason = match packet {
        Packet::VersionNegotiation(header, bytes) => {
            match check_version_negotiation(&header, bytes.as_ref(), &ids.made_with(), answered) {
                Ok(versions) => CloseReason::VersionNegotiation { versions },
                Err(_) => return ControlFlow::Continue(()),
            }
        }
        Packet::Retry(header, bytes) => {
            let backend = &lineage.get::<PacketProtectionBackend<T::Crypto>, Ibk>().0;
            let Ok(retry) =
                check_retry(backend, &header, bytes.as_ref(), &ids.made_with(), answered)
            else {
                return ControlFlow::Continue(());
            };
            let now = others.now();
            let went_on = restart_recovery::<T, L, B, S, Ls, Isj, If, Ile, Ikr, Hf, Ies>(
                lineage,
                others,
                link,
                now,
                |lineage, since_first_initial| {
                    <T::Side as Side>::on_retry(
                        &mut *lineage.get_mut::<<T::Side as Side>::Own, Iw>(),
                        &retry.received(since_first_initial),
                        retry.token().clone(),
                    ) == RetryDecision::Continue
                },
            );
            if went_on {
                let source = retry.source();
                let keys = retry_initial_keys(
                    &lineage.get::<PacketProtectionBackend<T::Crypto>, Ibk>().0,
                    &source,
                );
                let installed = lineage
                    .get_mut::<InitialKeys<T::Crypto>, Ii>()
                    .replace(keys);
                lineage.publish(installed);
                // a Retry changes the connection ID sent with, whatever the
                // strategy reports
                DestinationConnectionIdStrategy::<
                    LinkIdOf<T>,
                    InstantOf<T>,
                    ResetTokenRegistrarOf<T>,
                >::on_handshake_connection_id(
                    lineage
                        .get_mut::<ConnectionIdsOf<T>, Icid>()
                        .destination_mut(),
                    source,
                );
                lineage.publish(Happened::<DestinationConnectionIdsChanged>::new());
                lineage
                    .get_mut::<InitialDestinationConnectionIds, Iid>()
                    .retried(source);
                lineage.publish(Happened::<RetryReceived>::new());
                return ControlFlow::Continue(());
            }
            CloseReason::RetryAbandoned
        }
        Packet::Protected(_) => unreachable!("only a Retry or a Version Negotiation packet"),
    };
    let written = lineage
        .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
        .record(reason);
    if let Some(written) = written {
        lineage.publish(written);
    }
    let now = others.now();
    drain_each_link_path::<T, L, B, Il>(others, now);
    ControlFlow::Break(())
}

/// What path validation concluded closes the connection as `close` says:
/// silently ([`abort_on_failed_validation`]), or with NO_VIABLE_PATH, the
/// record keeping the reason written first.
fn close_on_failed_validation<T, L, B, Ic, Il, Ie>(
    lineage: &mut LineageOf<'_, T, L, LogicalPath>,
    others: &mut OtherNodes<'_, T, L, B>,
    close: PathValidationClose,
    now: InstantOf<T>,
) where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    B: CallBundle,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
{
    match close {
        PathValidationClose::Silently => {
            abort_on_failed_validation::<T, L, B, Ic, Il>(lineage, others, now);
        }
        PathValidationClose::NoViablePath => {
            let error = v1_error::<L, Ie>(ConnectionError::NoViablePath);
            let written = lineage
                .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .record(CloseReason::Local(Arc::new(LocalCloseCause::Connection(
                    error,
                ))));
            if let Some(written) = written {
                lineage.publish(written);
            }
        }
    }
}

/// A path validation of the active link path failed with no validated
/// path to return to: close the connection silently, discarding its state
/// without sending anything (RFC 9000 §9.3.2, MUST), for
/// [`AbortCause::PathValidationFailed`].
///
/// The record keeps the reason written first: a connection already closing
/// keeps its own reason and its close. Otherwise every link path drains,
/// ending at `now`, as when a client gives up after a Retry.
fn abort_on_failed_validation<T, L, B, Ic, Il>(
    lineage: &mut LineageOf<'_, T, L, LogicalPath>,
    others: &mut OtherNodes<'_, T, L, B>,
    now: InstantOf<T>,
) where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    B: CallBundle,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
{
    let written = lineage
        .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
        .record(CloseReason::Aborted(AbortCause::PathValidationFailed));
    let Some(written) = written else {
        return;
    };
    lineage.publish(written);
    drain_each_link_path::<T, L, B, Il>(others, now);
}

/// A server that processed a Handshake packet from the peer, which it
/// discards its Initial keys on, has the peer's address validated (RFC 9000
/// §8.1): the logical link the datagram arrived over is no longer held by
/// the anti-amplification limit, and what waits on the limit is woken.
fn validate_by_handshake<T, L, B, Ii, Ian>(
    lineage: &LineageOf<'_, T, L, layer::LogicalPath>,
    others: &mut OtherNodes<'_, T, L, B>,
    link: &LinkIdOf<T>,
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialKeys<T::Crypto>, Ii>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
{
    if <T::Side as Side>::ROLE != Role::Server
        || !matches!(
            lineage.get::<InitialKeys<T::Crypto>, Ii>(),
            InitialKeys::Discarded
        )
    {
        return;
    }
    let mut validated = false;
    if let Some(hlist_pat![mut limit, mut facts]) =
        others.link_entry::<HList![AntiAmplification, LinkFacts], Ian>(link)
        && facts.validation == AddressValidation::NotValidated
    {
        facts.validation = AddressValidation::Validated;
        limit.validated();
        validated = true;
    }
    if validated {
        others.publish_at(
            &NodeKey::LinkEntry(link.clone()),
            Happened::<AmplificationCreditChanged>::new(),
        );
    }
}

/// A datagram arrived over `link` for the logical path of this lend: when
/// its link path is still closing once the datagram was received, and its
/// close packet is sealed, the close packet counts one more datagram
/// received since it was sealed, which the link path's planner decides by
/// whether it goes again. Each datagram counts once, whatever its packets
/// were.
fn close_packet_received<T, L, B, Ir, Icp, Ipl>(
    others: &mut OtherNodes<'_, T, L, B>,
    link: &LinkIdOf<T>,
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    SendTypes<T, L>: HostSendStrategyTypes,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out: GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + GetAt<ClosePacket, Icp>
        + TakeEach<'s, HList![ClosePacket], Ipl>,
{
    let NodeKey::LogicalPath(path) = others.here().clone() else {
        unreachable!("a logical path's lend carries its key")
    };
    let key = NodeKey::LinkPath(path.clone(), link.clone());
    let mut closing = false;
    others.each_link_path_read::<LinkPathRole<InstantOf<T>>, Ir>(|each, role| {
        closing |= *each == key && matches!(role, LinkPathRole::Closing(_));
    });
    let mut sealed = false;
    others.each_link_path_read::<ClosePacket, Icp>(|each, packet| {
        sealed |= *each == key && packet.is_sealed();
    });
    if !(closing && sealed) {
        return;
    }
    let mut changed = None;
    if let Some(hlist_pat![mut packet]) = others.link_path::<HList![ClosePacket], Ipl>(&path, link)
    {
        changed = packet.datagram_received();
    }
    if let Some(changed) = changed {
        others.publish_at(&key, changed);
    }
}

/// What one packet the receiving call takes in is: one cut from a datagram,
/// or one that waited for its link path, opened.
// moved into its receiving at once, as large as the packet cut
#[allow(clippy::large_enum_variant)]
enum ReceiveInput<P, Lk: Link> {
    /// A packet cut from a datagram.
    Packet(ReceivedPacket<P, Lk>),
    /// A packet that waited for its link path.
    Opened(OpenedPacket<Lk>),
}

/// What receiving one packet came to, for the datagram it is from.
// the packet that waits is handed back by value
#[allow(clippy::large_enum_variant)]
enum Received<Lk: Link> {
    /// Go on with the next packet.
    Next,
    /// A connection error, or a silent close after a failed path
    /// validation: the rest of the datagram is dropped.
    Break,
    /// Changes of structure wait to be asked for: the datagram stops.
    Stopped,
    /// The packet waits for a link path over its logical link.
    AwaitingLinkPath(OpenedPacket<Lk>),
}

/// Receive `input` on the logical path of `lineage`: hold it when its keys
/// have not come; on a connection error write the error into the record of
/// why the connection closed, use up this poll's inputs and break, so that
/// what follows waits until the link paths have entered closing. A packet
/// processed goes to the migration rules ([`MigrationRules::processed`]),
/// whose requests wait in the logical path's input; a path validation it
/// concluded that leaves no path closes the connection silently and breaks. A packet that waits for
/// a link path is handed back when `may_build` and the connection is not
/// closing, and dropped otherwise.
#[allow(clippy::type_complexity)] // the positions of what it takes
fn receive_one<
    'v,
    T,
    L,
    B,
    Ip,
    Ic,
    Ii,
    Ih,
    Io,
    Iz,
    Ij,
    Im,
    Ia,
    It,
    Iu,
    Ikp,
    Ir,
    Ie,
    Ik,
    Hd,
    Icid,
    Iph,
    Iev,
    Hm,
    Il,
>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    input: ReceiveInput<<T::Link as Link>::Payload, T::Link>,
    may_build: bool,
) -> Received<T::Link>
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd> + StreamResetsOf,
    B: CallBundle,
    L: MigrationRules<T, Hm>,
    <T::Link as Link>::Payload: AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LogicalPathInput<T::Link, T::Receiver>, Ip>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<OwnZeroRttKeysOf<T>, Iz>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out: GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
{
    let (level, at, link, destination) = match &input {
        ReceiveInput::Packet(packet) => (
            packet.packet().level(),
            packet.arrival().at(),
            packet.arrival().link().id().clone(),
            destination_of(packet.packet()),
        ),
        ReceiveInput::Opened(opened) => (
            opened.level(),
            opened.arrival().at(),
            opened.arrival().link().id().clone(),
            opened.destination(),
        ),
    };
    let outcome = match input {
        ReceiveInput::Packet(packet) => receive_packet::<
            T,
            L,
            B,
            <T::Link as Link>::Payload,
            Ii,
            Ih,
            Io,
            Iz,
            Ij,
            Im,
            Ia,
            It,
            Iu,
            Ikp,
            Ir,
            Ie,
            Ik,
            Hd,
            Icid,
            Iph,
            Iev,
            Hm,
        >(lineage, others, packet),
        ReceiveInput::Opened(opened) => receive_opened::<
            T,
            L,
            B,
            <T::Link as Link>::Payload,
            Ii,
            Ih,
            Io,
            Iz,
            Ij,
            Im,
            Ia,
            It,
            Iu,
            Ikp,
            Ir,
            Ie,
            Ik,
            Hd,
            Icid,
            Iph,
            Iev,
            Hm,
        >(lineage, others, opened),
    };
    match outcome {
        Ok(PacketOutcome::Processed {
            highest_numbered,
            non_probing,
        }) => {
            let mut requests = Vec::new();
            <L as MigrationRules<T, Hm>>::processed(
                lineage,
                others,
                &link,
                &destination,
                highest_numbered && non_probing,
                at,
                &mut requests,
            );
            // what the packet's PATH_RESPONSE concluded
            if let Some(close) =
                <L as MigrationRules<T, Hm>>::concluded(lineage, others, at, &mut requests)
            {
                close_on_failed_validation::<T, L, B, Ic, Il, Ie>(lineage, others, close, at);
                return Received::Break;
            }
            if requests.is_empty() {
                return Received::Next;
            }
            lineage
                .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
                .requests
                .extend(requests.into_iter().map(ReceiveRequest::Migration));
            Received::Stopped
        }
        Ok(PacketOutcome::Closing) => Received::Next,
        Ok(PacketOutcome::AwaitingLinkPath(opened)) => {
            let closing = lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .is_written();
            if may_build && !closing {
                return Received::AwaitingLinkPath(opened);
            }
            dropped::<T, L, Iev>(lineage, at, level, &DropReason::NoLinkPath);
            Received::Next
        }
        Ok(PacketOutcome::Dropped(reason)) => {
            dropped::<T, L, Iev>(lineage, at, level, &reason);
            Received::Next
        }
        Ok(PacketOutcome::Held(packet)) => {
            lineage
                .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
                .hold(HeldInput::Packet(packet));
            Received::Next
        }
        Err(error) => {
            let written = lineage
                .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .record(CloseReason::Local(Arc::new(LocalCloseCause::Connection(
                    error,
                ))));
            if let Some(written) = written {
                lineage.publish(written);
            }
            lineage
                .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
                .use_up();
            Received::Break
        }
    }
}

/// Give the connection's events `read`, the Initial packets read with the
/// first flight before the connection was made, as received.
fn first_flight_received<T, L, Iev>(
    lineage: &mut LineageOf<'_, T, L, LogicalPath>,
    read: Vec<FirstFlightPacket<InstantOf<T>>>,
) where
    T: Choices,
    L: LineagePartList<T>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
{
    for packet in read {
        let mut sink = lineage.get_mut::<ConnectionEventSink<EventsOf<T, L>>, Iev>();
        let Some(events) = sink.active::<InstantOf<T>>() else {
            return;
        };
        let plain = PlainPacket {
            level: EncryptionLevel::Initial,
            number: packet.number,
            bytes: &packet.bytes,
            header_len: packet.header_len,
            wire_len: packet.wire_len,
            pmtu_probe: false,
        };
        <EventsOf<T, L> as PacketEvents<InstantOf<T>, L>>::packet_received(
            events, packet.at, &plain,
        );
    }
}

/// Record in the connection's events that a packet of `level`, arrived at
/// `at`, was dropped for `reason`.
fn dropped<T, L, Iev>(
    lineage: &mut LineageOf<'_, T, L, LogicalPath>,
    at: InstantOf<T>,
    level: EncryptionLevel,
    reason: &DropReason,
) where
    T: Choices,
    L: LineagePartList<T>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
{
    if <EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED
        && let Some(events) = lineage
            .get_mut::<ConnectionEventSink<EventsOf<T, L>>, Iev>()
            .active::<InstantOf<T>>()
    {
        events.packet_dropped(at, Some(level), reason);
    }
}

/// Wake the receiving call when a stateless reset is received for its
/// logical path; once one was, write [`CloseReason::StatelessReset`] into
/// the record of why the connection closed and drain every link path (RFC
/// 9000 §10.3.1), as a CONNECTION_CLOSE frame from the peer does.
///
/// The record keeps the reason written first: a connection already closing
/// keeps its own reason and only drains, each link path keeping its end
/// (§10.2.2). Once every link path drains there is nothing left to do, and
/// the mark is no longer acted on.
#[allow(clippy::type_complexity)] // the positions of what it takes
fn drain_on_stateless_reset<'v, T, L, B, Ic, Ir, Is, Iv, Ima, Irt, Il>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    cx: &Context<'_>,
) where
    T: Choices,
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace> + ConnectionErrorsOf,
    B: CallBundle,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<Arc<StatelessResetSignal>, Is>
        + ReadEach<LinkPathRoleReads<T, L>, Iv>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out: GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
{
    // registered before the mark is looked at, so that a reset received in
    // between still wakes the call
    let signal = lineage.get::<Arc<StatelessResetSignal>, Is>();
    signal.register(cx.waker());
    if !signal.received() {
        return;
    }
    let mut all_draining = true;
    others.each_link_path_read::<LinkPathRole<InstantOf<T>>, Ir>(|_, role| {
        all_draining &= matches!(role, LinkPathRole::Draining(_));
    });
    if all_draining {
        return;
    }
    let written = lineage
        .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
        .record(CloseReason::StatelessReset);
    if let Some(written) = written {
        lineage.publish(written);
    }
    drain_link_paths::<T, L, B, Iv, Ima, Irt, Il>(lineage, others);
}

/// The length of the Destination Connection ID of a short header in a
/// datagram routed as `route` says: the length the interpretation read,
/// and after a long header that of the connection ID it was found by, which
/// every packet of the datagram carries (RFC 9000 §12.2).
pub(super) fn short_dcid_len<Local>(route: &DatagramRouteMatchInfo<Local>) -> ConnectionIdLength {
    match route.interpretation() {
        FirstPacketInterpretation::Short { dcid_len } => dcid_len,
        FirstPacketInterpretation::Long { .. } | FirstPacketInterpretation::VersionNegotiation => {
            match route.association() {
                MatchAssociation::LocalCid(cid) | MatchAssociation::InitialDcid(cid) => {
                    AsRef::<ConnectionId>::as_ref(cid).length()
                }
                MatchAssociation::ZeroCid(_) => ConnectionIdLength::ZERO,
            }
        }
    }
}

/// Whether the first packet of `datagram`, a 1-RTT packet whose
/// Destination Connection ID is `dcid_len` long, opens with `keys`, its
/// packet number decoded against `largest` and its generation selected
/// against `lowest` as [`open_one_rtt`] does. A copy is opened: the datagram
/// stays as it arrived, and nothing is recorded or counted.
fn first_packet_opens<B: CryptoBackend, I: Copy>(
    keys: &OneRttReceiveKeys<B, I>,
    lowest: Option<PacketNumber>,
    datagram: &[u8],
    dcid_len: ConnectionIdLength,
    largest: Option<PacketNumber>,
) -> bool {
    let Some(Ok(Packet::Protected(packet @ ProtectedPacket::OneRtt(..)))) =
        into_packets(datagram, dcid_len).next()
    else {
        return false;
    };
    let Some(pn_offset) = packet_number_offset(&packet) else {
        return false;
    };
    let mut copy = packet.into_bytes().to_vec();
    open_one_rtt(keys, lowest, &mut copy, pn_offset, largest).is_ok()
}

/// The receiving call of a logical path; the steps are those of the
/// [module documentation](self).
#[call(yields = W::Request)]
pub async fn logical_path_receiving<W: LogicalPathReceivingCapability>(
    host: &mut impl LentAccess<Family = W>,
) {
    loop {
        while let Some(request) = host.with(|mut view| W::next_request(view.as_pin())) {
            yield request;
        }
        let delivery =
            poll_fn(|cx| host.with(|mut view| W::poll_next_input(view.as_pin(), cx))).await;
        let Some(delivery) = delivery else {
            continue;
        };
        let delivery = match delivery {
            DatagramDelivery::Exclusive(delivery) => delivery,
            DatagramDelivery::Competing(candidate) => {
                let attempt = candidate
                    .try_exclusive(|access, route| {
                        host.with(|mut view| W::judge(view.as_pin(), access, route))
                    })
                    .await;
                match attempt {
                    DatagramClaimAttempt::Claimed(delivery, ())
                    | DatagramClaimAttempt::Exclusive(delivery) => delivery,
                    DatagramClaimAttempt::Unclaimed(candidate) => {
                        host.with(|mut view| W::hold_candidate(view.as_pin(), candidate));
                        continue;
                    }
                    DatagramClaimAttempt::Abandoned(())
                    | DatagramClaimAttempt::ClaimedElsewhere => {
                        continue;
                    }
                }
            }
        };
        host.with(|mut view| W::receive_datagram(view.as_pin(), delivery));
    }
}

/// The kind of the receiving call of a logical path. It subscribes to the
/// 0-RTT, Handshake and 1-RTT keys installed and discarded: once they are
/// installed, or a server decided on 0-RTT, the inputs held for them go.
#[derive(Debug)]
pub struct LogicalPathReceivingKind;

impl<
    T,
    L,
    Ip,
    Ic,
    Ii,
    Ih,
    Io,
    Iz,
    Ij,
    Im,
    Ia,
    It,
    Iu,
    Ikp,
    Ir,
    Ie,
    Ik,
    Hd,
    Ian,
    Icid,
    Iph,
    Iev,
    Icp,
    Ipl,
    Is,
    Iv,
    Ima,
    Irt,
    Il,
    Iid,
    Ibk,
    Iw,
    Isj,
    If,
    Ile,
    Ikr,
    Hf,
    Ies,
    S,
    Ls,
    Hm,
>
    CallKind<
        T,
        L,
        LogicalPath,
        Positions<
            Ip,
            Ic,
            Ii,
            Ih,
            Io,
            Iz,
            Ij,
            Im,
            Ia,
            It,
            Iu,
            Ikp,
            Ir,
            Ie,
            Ik,
            Hd,
            Ian,
            Icid,
            Iph,
            Iev,
            Icp,
            Ipl,
            Is,
            Iv,
            Ima,
            Irt,
            Il,
            Iid,
            Ibk,
            Iw,
            Isj,
            If,
            Ile,
            Ikr,
            Hf,
            Ies,
            S,
            Ls,
            Hm,
        >,
    > for LogicalPathReceivingKind
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd> + StreamResetsOf,
    L: FeedbackSummariesOf + EstablishedSourceComponentsOf<T, L>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    L: MigrationRules<T, Hm>,
    S: 'static,
    Ls: 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialDestinationConnectionIds, Iid>
        + GetAt<PacketProtectionBackend<T::Crypto>, Ibk>
        + GetAt<<T::Side as Side>::Own, Iw>
        + GetAt<SendJournalsOf<T, L>, Isj>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ile>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, RestartRecoveryTakes<T, L, S, Ls>, Ikr>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Ies>,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LogicalPathInput<T::Link, T::Receiver>, Ip>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<OwnZeroRttKeysOf<T>, Iz>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + GetAt<PeerHandshakeConnectionId, Iph>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    EventsOf<T, L>: PacketEvents<InstantOf<T>, L>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<ClosePacket, Icp> + TakeEach<'s, HList![ClosePacket], Ipl>,
    SendTypes<T, L>: HostSendStrategyTypes,
    L: ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        GetAt<Arc<StatelessResetSignal>, Is> + ReadEach<LinkPathRoleReads<T, L>, Iv>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
    Positions<
        Ip,
        Ic,
        Ii,
        Ih,
        Io,
        Iz,
        Ij,
        Im,
        Ia,
        It,
        Iu,
        Ikp,
        Ir,
        Ie,
        Ik,
        Hd,
        Ian,
        Icid,
        Iph,
        Iev,
        Icp,
        Ipl,
        Is,
        Iv,
        Ima,
        Irt,
        Il,
        Iid,
        Ibk,
        Iw,
        Isj,
        If,
        Ile,
        Ikr,
        Hf,
        Ies,
        S,
        Ls,
        Hm,
    >: 'static,
{
    type Call<B: CallBundle> = LentCall<
        NodeCallFamily<
            T,
            L,
            LogicalPath,
            LogicalPathReceivingKind,
            Positions<
                Ip,
                Ic,
                Ii,
                Ih,
                Io,
                Iz,
                Ij,
                Im,
                Ia,
                It,
                Iu,
                Ikp,
                Ir,
                Ie,
                Ik,
                Hd,
                Ian,
                Icid,
                Iph,
                Iev,
                Icp,
                Ipl,
                Is,
                Iv,
                Ima,
                Irt,
                Il,
                Iid,
                Ibk,
                Iw,
                Isj,
                If,
                Ile,
                Ikr,
                Hf,
                Ies,
                S,
                Ls,
                Hm,
            >,
            B,
        >,
        LogicalPathReceiving,
    >;
    fn start<B: CallBundle>(_: &mut ArgsOf<T, L, LogicalPath>) -> Self::Call<B> {
        LentCall::new(LogicalPathReceiving::new())
    }
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<PathValidationConcluded>()
            .add::<KeysInstalled<level::ZeroRtt>>()
            .add::<KeysDiscarded<level::ZeroRtt>>()
            .add::<KeysInstalled<level::Handshake>>()
            .add::<KeysDiscarded<level::Handshake>>()
            .add::<KeysInstalled<level::OneRtt>>()
            .add::<KeysDiscarded<level::OneRtt>>();
    }
}
