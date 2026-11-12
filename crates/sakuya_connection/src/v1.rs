//! QUIC version 1 in a connection: the part, what it chooses, and its
//! components.
//!
//! [`Part`] is version 1 as one part of a composition. Its shares put the
//! keys of each encryption level, the transport parameters, the idle
//! timeout and what the connection was made with for its first logical
//! link in the connection node, with the recovery factory and the record of
//! why the connection closed ([`close`]); the clone of the
//! link, the facts about it and the anti-amplification limit in the entry of
//! each logical link; the role in each link path; and in each link path's
//! recovery layer, what the factory makes for it with the state beside them,
//! its loss detection state for each packet number space and its probe
//! timeout. Each logical path keeps, for each packet number space, its
//! packet number state, its receive journals and its ACK obligation. Once
//! a reason for closing is written, the link paths close, their recovery
//! layers and the established layer end, and the connection ends with its
//! last link path. The calls and the send journals are not here yet.

pub mod amplification;
pub mod close;
pub mod confirmation;
pub mod crypto;
pub mod error;
pub mod idle;
pub mod keys;
pub mod link;
pub mod loss_detection;
pub mod parameters;
pub mod pto;
pub mod recovery;
pub mod role;
pub mod spaces;

#[cfg(test)]
mod tests;

use core::{fmt::Debug, time::Duration};

use sakuya_packet_protection::{
    backend::CryptoBackend,
    initial::{INITIAL_AEAD, InitialSecrets},
    secret::TrafficSecret,
};
use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::{ParametersOf, ParametersPart},
    parts::{HList, HNil, Selector},
    v1::transport_parameters::{
        TransportParameterSlots, TransportParameterSpace,
        integer::{MaxAckDelay, MaxIdleTimeout},
    },
};

use crate::{
    call::CallBundle,
    clock::{CheckedAdd, ConnectionChoices, InstantOf},
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, ReadSet,
        RequestOf,
    },
    error::{ConnectionErrorOf, ConnectionErrorPart, ConnectionErrorsOf},
    layer::{self, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    share::{
        ConnectionArgsOf, FlatMut, LayerShare, LineageLists, LineagePartList, LogicalPathKeyShare,
        LogicalPathKeys, NodeData,
    },
    take::{GetAt, ReadEach},
};

use self::{
    amplification::{AddressValidation, AntiAmplification, AntiAmplificationFactor},
    close::{ApplicationClose, CloseReasonRecord, LocalCloseCause},
    confirmation::HandshakeConfirmation,
    idle::IdleTimeout,
    keys::{DirectionKeys, HandshakeKeys, InitialKeys, LevelKeys, OneRttKeys},
    link::{FirstLinkStart, LinkClone, LinkFacts},
    loss_detection::LossDetectionOf,
    parameters::{LocalTransportParameters, PeerTransportParameters},
    pto::ProbeTimeout,
    recovery::{
        CongestionPartOf, LinkPathCongestionState, OthersOf, PmtuOf, RecoveryConfigOf,
        RecoveryFactoryOf, RttOf,
    },
    role::LinkPathRole,
    spaces::{AckObligationsOf, DEFAULT_MAX_ACK_DELAY, peer_max_ack_delay},
};
use sakuya_recovery::{
    ack_obligation::AckObligation,
    factory::{LendCongestion, RecoveryFactory},
    loss::LossThresholds,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    pto::probe_timeout,
    receive_journals::{MaxAckRanges, ReceiveJournals},
    rtt::RttEstimator,
};
use sakuya_stream::connection::CloseReason;
use sakuya_tls::engine::HandshakeError;

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

/// Version 1 finds its own [`ConnectionError`](error::ConnectionError).
impl ConnectionErrorPart for Part {
    type ConnectionError = error::ConnectionError;
}

/// What a composition chooses for version 1.
pub trait Choices: ConnectionChoices {
    /// The cryptographic backend that derives the packet protection keys.
    type Crypto: CryptoBackend + 'static;
    /// Which side of the connection this side is.
    type Side: Side;
    /// What makes the RTT estimate, the stored part of congestion control
    /// and the datagram size probing policy of each link path, one for each
    /// connection. `V` identifies a link path, as found from the list of
    /// parts: the logical link when the connection supports version 1
    /// alone.
    type Recovery<V: Clone + Eq + Debug + 'static>: RecoveryFactory<Self::Link, Via = V> + 'static;
    /// What decides when an ACK frame is due, one for each packet number
    /// space of a logical path.
    type AckObligation: AckObligation<InstantOf<Self>> + 'static;
    /// The application's own error type for closing the connection.
    type ApplicationError: ApplicationClose + 'static;
    /// How the handshake engine of this side fails with an alert: the
    /// failure that [`HandshakeError`] holds for it.
    ///
    /// This item is provisional: it is to follow from the handshake engine
    /// of the side.
    type HandshakeFailure: 'static;
}

/// This endpoint's reason for closing a connection of the choices `T` and
/// the list of parts `L`: the connection's error, the handshake's error or
/// the application's error.
pub type CloseCauseOf<T, L> = LocalCloseCause<
    ConnectionErrorOf<L>,
    HandshakeError<<T as Choices>::HandshakeFailure, ConnectionErrorOf<L>>,
    <T as Choices>::ApplicationError,
>;

/// What differs between the two sides of a connection: one method for each
/// difference.
pub trait Side: 'static {
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
}

/// The server's side.
#[derive(Debug)]
pub struct Server;

impl Side for Server {
    fn split_initial_secrets(secrets: InitialSecrets) -> (TrafficSecret, TrafficSecret) {
        (secrets.server, secrets.client)
    }
    fn later_link_validation() -> AddressValidation {
        AddressValidation::NotValidated
    }
    fn peer_validates_address_implicitly() -> bool {
        true
    }
}

/// The client's side.
#[derive(Debug)]
pub struct Client;

impl Side for Client {
    fn split_initial_secrets(secrets: InitialSecrets) -> (TrafficSecret, TrafficSecret) {
        (secrets.client, secrets.server)
    }
    fn later_link_validation() -> AddressValidation {
        AddressValidation::Validated
    }
    fn peer_validates_address_implicitly() -> bool {
        false
    }
}

/// What version 1 needs to make the connection node, given once by whoever
/// makes the connection.
///
/// The start state of the handshake engine joins these when the advancing
/// call is written.
pub struct ConnectionArgs<T: Choices, L: LogicalPathKeys> {
    /// The backend the Initial keys are derived with.
    pub crypto: T::Crypto,
    /// The Destination Connection ID of the client's first Initial packet,
    /// which the Initial secrets are derived from (RFC 9001 §5.2): the one a
    /// client chose, the one a server found in the first datagrams.
    pub client_dcid: ConnectionId,
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
}

impl<T: Choices, L: ParametersOf<TransportParameterSpace> + LogicalPathKeys + ConnectionErrorsOf>
    LayerShare<T, L, layer::Connection> for Part
{
    type Data = HList![
        InitialKeys<T::Crypto>,
        HandshakeKeys<T::Crypto>,
        OneRttKeys<T::Crypto>,
        AntiAmplificationFactor,
        FirstLinkStart,
        IdleTimeout<InstantOf<T>>,
        LocalTransportParameters<TransportParameterSlots>,
        PeerTransportParameters<TransportParameterSlots<L>>,
        RecoveryFactoryOf<T, L>,
        LossThresholds,
        MaxAckRanges,
        HandshakeConfirmation,
        CloseReasonRecord<CloseCauseOf<T, L>>,
    ];
    type Calls = HNil;
    type Args = ConnectionArgs<T, L>;
}
impl<T: Choices, L> LayerShare<T, L, layer::LinkEntry> for Part {
    type Data = HList![LinkClone<T::Link>, LinkFacts, AntiAmplification];
    type Calls = HNil;
}
impl<T: Choices, L> LayerShare<T, L, layer::LogicalPath> for Part {
    type Data = HList![
        PacketNumberSpaces<PacketNumberSpaceState>,
        PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>,
        AckObligationsOf<T>,
    ];
    type Calls = HNil;
}
impl<T: Choices, L> LayerShare<T, L, layer::LinkPath> for Part {
    type Data = HList![LinkPathRole<InstantOf<T>>];
    type Calls = HNil;
}
impl<T: Choices, L> LayerShare<T, L, layer::Established> for Part {
    type Data = HNil;
    type Calls = HNil;
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
        LossDetectionOf<T, L>,
        ProbeTimeout<InstantOf<T>>,
    ];
    /// The factory makes the first three together.
    type Units = HList![
        HList![RttOf<T, L>, CongestionPartOf<T, L>, PmtuOf<T, L>],
        HList![LinkPathCongestionState<InstantOf<T>>],
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
    let granularity = thresholds.granularity();
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
/// is live from the start (RFC 9001 §5.2).
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
        let secrets = InitialSecrets::derive(&args.crypto, &args.client_dcid);
        let (send, receive) = T::Side::split_initial_secrets(secrets);
        InitialKeys::Live(LevelKeys {
            send: DirectionKeys::derive(&args.crypto, INITIAL_AEAD, &send),
            receive: DirectionKeys::derive(&args.crypto, INITIAL_AEAD, &receive),
        })
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
not_yet!(HandshakeKeys, OneRttKeys);

macro_rules! discarded_when_draining {
    ($($ty:ident),*) => {$(
        /// The keys of a level read the roles of the link paths: once every
        /// link path is `Draining`, nothing is sent or processed any more,
        /// and the keys are discarded (RFC 9000 §10.2.2).
        ///
        /// Not here yet: keeping only the receiving half while closing, once
        /// every closing link path has sealed its close packet.
        impl<T: Choices, L, I, J> DataComponent<T, L, layer::Connection, (I, J)> for $ty<T::Crypto>
        where
            L: LineagePartList<T>,
            for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<$ty<T::Crypto>, I>,
            for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
            for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
                GetAt<LinkPathRole<InstantOf<T>>, J>,
        {
            fn reads(reads: &mut ReadSet) {
                reads.add::<LinkPathRole<InstantOf<T>>>();
            }
            fn reread<'v, B: CallBundle>(
                mut lineage: LineageOf<'v, T, L, layer::Connection>,
                others: &mut OtherNodes<'v, T, L, B>,
                _: InstantOf<T>,
            ) -> Option<RequestOf<T, L>> {
                if matches!(lineage.get::<$ty<T::Crypto>, I>(), $ty::Discarded) {
                    return None;
                }
                let (mut any, mut all_draining) = (false, true);
                others.each_link_path_read::<LinkPathRole<InstantOf<T>>, J>(|_, role| {
                    any = true;
                    all_draining &= matches!(role, LinkPathRole::Draining(_));
                });
                if any && all_draining {
                    lineage.get_mut::<$ty<T::Crypto>, I>().discard();
                }
                None
            }
        }
    )*};
}
discarded_when_draining!(InitialKeys, HandshakeKeys, OneRttKeys);

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

/// No connection starts closing.
impl<T: Choices, L: ConnectionErrorsOf> Build<T, L, layer::Connection, ()>
    for CloseReasonRecord<CloseCauseOf<T, L>>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        CloseReasonRecord::new()
    }
}

/// The record reads itself, which whoever finds a reason for closing
/// writes, and the roles of the link paths. Once it is written, it asks for
/// the established layer to end; once it is written and no link path is
/// left, for the connection to end: each link path ends when its closing or
/// draining period does. An end without such a period, such as the idle
/// timeout's, asks for the connection to end where it writes the reason.
impl<T: Choices, L: ConnectionErrorsOf, I> DataComponent<T, L, layer::Connection, (I,)>
    for CloseReasonRecord<CloseCauseOf<T, L>>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, I>,
{
    fn reads(reads: &mut ReadSet) {
        reads
            .add::<CloseReasonRecord<CloseCauseOf<T, L>>>()
            .add::<LinkPathRole<InstantOf<T>>>();
    }
    fn reread<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, layer::Connection>,
        others: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        if !lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, I>()
            .is_written()
        {
            return None;
        }
        if others.link_path_keys().next().is_none() {
            Some(StructureRequest::EndConnection)
        } else if others.has_established() {
            Some(StructureRequest::EndEstablished)
        } else {
            None
        }
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

/// The idle timeout reads itself, which the calls restart, both sides'
/// transport parameters (this side's once they are sent, the peer's once
/// they are known) and the RTT estimates of the recovery layers. Its floor
/// is three probe timeouts: the largest among the link paths with a
/// recovery layer, without backoff, as in the Application Data space. When
/// it expires the connection ends at once, without a closing period (RFC
/// 9000 §10.1), and the reason goes into the record of why the connection
/// closed; a reason already there stays.
impl<T: Choices, L, Ii, Iv, Ic, Is, Ima, Ir>
    DataComponent<T, L, layer::Connection, ((Ii, Iv, Ic), (Is, Ima, Ir))>
    for IdleTimeout<InstantOf<T>>
where
    L: LineagePartList<T>,
    L: ParametersOf<TransportParameterSpace> + ConnectionErrorsOf,
    TransportParameterSlots<L>:
        Selector<Option<MaxIdleTimeout>, Is> + Selector<Option<MaxAckDelay>, Ima>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<IdleTimeout<InstantOf<T>>, Ii>
        + ReadEach<IdleTimeoutReads<L>, Iv>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Ir>,
{
    fn reads(reads: &mut ReadSet) {
        reads
            .add::<IdleTimeout<InstantOf<T>>>()
            .add_each::<IdleTimeoutReads<L>>()
            .add::<RttOf<T, L>>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Connection>) -> Option<InstantOf<T>> {
        lineage.get::<IdleTimeout<InstantOf<T>>, Ii>().deadline()
    }
    fn expire<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        lineage
            .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .record(CloseReason::IdleTimeout);
        Some(StructureRequest::EndConnection)
    }
    fn reread<'v, B: CallBundle>(
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
        // takes the timeout only to change it: it reads itself
        let idle = lineage.get::<IdleTimeout<InstantOf<T>>, Ii>();
        let peer = peer.unwrap_or(idle.peer());
        // with no recovery layer the last probe timeout stays
        let pto = pto.unwrap_or(idle.probe_timeout());
        if (idle.local(), idle.peer(), idle.probe_timeout()) != (local, peer, pto) {
            let idle = lineage.get_mut::<IdleTimeout<InstantOf<T>>, Ii>();
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

/// The limit starts with nothing received or sent, by the configured
/// factor.
impl<T: Choices, L, I> Build<T, L, layer::LinkEntry, I> for AntiAmplification
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<AntiAmplificationFactor, I>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LinkEntry>,
        _: &mut ArgsOf<T, L, layer::LinkEntry>,
    ) -> Self {
        AntiAmplification::new(*parents.get::<AntiAmplificationFactor, I>())
    }
}
impl PassiveDataComponent for AntiAmplification {}

// ---- the link path ----

/// The connection's first link path is active from the start: the
/// handshake runs over it. A later one is a candidate until it is
/// validated.
impl<T: Choices, L, I> Build<T, L, layer::LinkPath, I> for LinkPathRole<InstantOf<T>>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::LinkPathParents: GetAt<FirstLinkStart, I>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        _: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        if parents.get_mut::<FirstLinkStart, I>().take_path() {
            LinkPathRole::Active
        } else {
            LinkPathRole::Candidate
        }
    }
}

/// The role's end time is its deadline: when it comes the link path ends.
/// It reads itself, which other components change, and the record of why
/// the connection closed, and asks for the recovery layer to follow the
/// role: built when the link path is `Active` without one, ended when the
/// role has none. A link path built `Active`, the connection's first, so
/// gets its layer as soon as it is built.
///
/// Once the record is written, a candidate ends, and an `Active` or
/// `Settling` link path enters `Closing` for three times the current probe
/// timeout (RFC 9000 §10.2), measured when it enters; a link path already
/// `Closing` or `Draining` keeps its role. Whoever finds that the peer
/// closed puts the link paths into `Draining` itself.
///
/// Not here yet: the initial RTT of a later link path whose new address
/// was validated, which comes with path validation. It asks for the layer
/// of an `Active` link path without an initial RTT.
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
    fn reads(reads: &mut ReadSet) {
        reads
            .add::<LinkPathRole<InstantOf<T>>>()
            .add::<CloseReasonRecord<CloseCauseOf<T, L>>>();
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
    fn reread<'v, B: CallBundle>(
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
                    lineage
                        .get_mut::<LinkPathRole<InstantOf<T>>, I>()
                        .close(end);
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
/// why the connection closed and the RTT estimates; it is not reread when
/// these change.
type LinkPathRoleReads<T, L> = HList![
    PeerTransportParameters<TransportParameterSlots<L>>,
    LossThresholds,
    IdleTimeout<InstantOf<T>>
];
