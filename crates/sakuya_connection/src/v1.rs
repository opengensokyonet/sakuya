//! QUIC version 1 in a connection: the part, what it chooses, and its
//! components.
//!
//! [`Part`] is version 1 as one part of a composition. Its shares put the
//! keys of each encryption level, the transport parameters, the idle
//! timeout and what the connection was made with for its first logical
//! link in the connection node; the clone of the link, the facts about it
//! and the anti-amplification limit in the entry of each logical link; and
//! the role in each link path. The calls and the components of the logical
//! path and the recovery layer are not here yet.

pub mod amplification;
pub mod idle;
pub mod keys;
pub mod link;
pub mod parameters;
pub mod role;

#[cfg(test)]
mod tests;

use core::time::Duration;

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
        TransportParameterSlots, TransportParameterSpace, integer::MaxIdleTimeout,
    },
};

use crate::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    layer::{self, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    share::{ConnectionArgsOf, LayerShare, LineageLists, LogicalPathKeyShare},
    take::GetAt,
};

use self::{
    amplification::{AddressValidation, AntiAmplification, AntiAmplificationFactor},
    idle::IdleTimeout,
    keys::{DirectionKeys, HandshakeKeys, InitialKeys, LevelKeys, OneRttKeys},
    link::{FirstLinkStart, LinkClone, LinkFacts},
    parameters::{LocalTransportParameters, PeerTransportParameters},
    role::LinkPathRole,
};

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

/// What a composition chooses for version 1.
pub trait Choices: ConnectionChoices {
    /// The cryptographic backend that derives the packet protection keys.
    type Crypto: CryptoBackend + 'static;
    /// Which side of the connection this side is.
    type Side: Side;
}

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
}

/// What version 1 needs to make the connection node, given once by whoever
/// makes the connection.
///
/// The start state of the handshake engine joins these when the advancing
/// call is written.
pub struct ConnectionArgs<T: Choices> {
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
}

impl<T: Choices, L: ParametersOf<TransportParameterSpace>> LayerShare<T, L, layer::Connection>
    for Part
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
    ];
    type Calls = HNil;
    type Args = ConnectionArgs<T>;
}
impl<T: Choices, L> LayerShare<T, L, layer::LinkEntry> for Part {
    type Data = HList![LinkClone<T::Link>, LinkFacts, AntiAmplification];
    type Calls = HNil;
}
impl<T: Choices, L> LayerShare<T, L, layer::LogicalPath> for Part {
    type Data = HNil;
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
impl<T: Choices, L> LayerShare<T, L, layer::Recovery> for Part {
    type Data = HNil;
    type Calls = HNil;
}

/// Version 1's facts among the facts of the connection node.
fn own_args<T: Choices, L, I>(args: &mut ArgsOf<T, L, layer::Connection>) -> &mut ConnectionArgs<T>
where
    for<'v> L: LineageLists<'v, T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T>, I>,
{
    args.get_mut()
}

/// The maximum idle timeout among version 1's transport parameters:
/// `None` when it is absent or zero.
fn max_idle_timeout<S: Selector<Option<MaxIdleTimeout>, I>, I>(slots: &S) -> Option<Duration> {
    let millis = u64::from(slots.get().as_ref()?.get());
    Some(Duration::from_millis(millis)).filter(|timeout| !timeout.is_zero())
}

// ---- the connection node ----

/// The Initial keys are derived when the connection is made, so the level
/// is live from the start (RFC 9001 §5.2).
impl<T: Choices, L, I> Build<T, L, layer::Connection, I> for InitialKeys<T::Crypto>
where
    for<'v> L: LineageLists<'v, T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T>, I>,
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
impl<T: Choices, L> DataComponent<T, L, layer::Connection, ()> for InitialKeys<T::Crypto> where
    for<'v> L: LineageLists<'v, T>
{
}

macro_rules! not_yet {
    ($($ty:ident),*) => {$(
        /// The handshake produces them later.
        impl<T: Choices, L> Build<T, L, layer::Connection, ()> for $ty<T::Crypto>
        where
            for<'v> L: LineageLists<'v, T>,
        {
            fn build<'v>(
                _: &mut ParentsOf<'v, T, L, layer::Connection>,
                _: &mut ArgsOf<T, L, layer::Connection>,
            ) -> Self {
                $ty::NotYet
            }
        }
        impl<T: Choices, L> DataComponent<T, L, layer::Connection, ()> for $ty<T::Crypto> where
            for<'v> L: LineageLists<'v, T>
        {
        }
    )*};
}
not_yet!(HandshakeKeys, OneRttKeys);

impl<T: Choices, L, I> Build<T, L, layer::Connection, I> for AntiAmplificationFactor
where
    for<'v> L: LineageLists<'v, T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        own_args::<T, L, I>(args).anti_amplification
    }
}
impl<T: Choices, L> DataComponent<T, L, layer::Connection, ()> for AntiAmplificationFactor where
    for<'v> L: LineageLists<'v, T>
{
}

impl<T: Choices, L, I> Build<T, L, layer::Connection, I> for FirstLinkStart
where
    for<'v> L: LineageLists<'v, T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        FirstLinkStart::new(own_args::<T, L, I>(args).first_link)
    }
}
impl<T: Choices, L> DataComponent<T, L, layer::Connection, ()> for FirstLinkStart where
    for<'v> L: LineageLists<'v, T>
{
}

/// The idle timeout starts from this side's maximum idle timeout as
/// configured.
impl<T: Choices, L, I> Build<T, L, layer::Connection, I> for IdleTimeout<InstantOf<T>>
where
    for<'v> L: LineageLists<'v, T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T>, I>,
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

/// The idle timeout reads itself, which the calls restart, and both sides'
/// transport parameters: this side's once they are sent, the peer's once
/// they are known. When it expires the
/// connection ends at once, without a closing period (RFC 9000 §10.1).
///
/// Not here yet: the floor of three probe timeouts, which reads the
/// recovery layers, and the record of why the connection closed.
impl<T: Choices, L, Ii, Il, Ip, Is> DataComponent<T, L, layer::Connection, (Ii, Il, Ip, Is)>
    for IdleTimeout<InstantOf<T>>
where
    for<'v> L: LineageLists<'v, T>,
    L: ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<MaxIdleTimeout>, Is>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<IdleTimeout<InstantOf<T>>, Ii>
        + GetAt<LocalTransportParameters<TransportParameterSlots>, Il>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ip>,
{
    fn reads(reads: &mut ReadSet) {
        reads
            .add::<IdleTimeout<InstantOf<T>>>()
            .add::<LocalTransportParameters<TransportParameterSlots>>()
            .add::<PeerTransportParameters<TransportParameterSlots<L>>>();
    }
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::Connection>) -> Option<InstantOf<T>> {
        lineage.get::<IdleTimeout<InstantOf<T>>, Ii>().deadline()
    }
    fn expire<'v, B: CallBundle>(
        _: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        Some(StructureRequest::EndConnection)
    }
    fn reread<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let local = lineage.get::<LocalTransportParameters<TransportParameterSlots>, Il>();
        let local = local
            .sent()
            .or(local.configured())
            .and_then(max_idle_timeout);
        let peer = lineage
            .get::<PeerTransportParameters<TransportParameterSlots<L>>, Ip>()
            .known()
            .map(max_idle_timeout);
        // takes the timeout only to change it: it reads itself
        let idle = lineage.get::<IdleTimeout<InstantOf<T>>, Ii>();
        let peer = peer.unwrap_or(idle.peer());
        if (idle.local(), idle.peer()) != (local, peer) {
            let idle = lineage.get_mut::<IdleTimeout<InstantOf<T>>, Ii>();
            idle.set_local(local);
            idle.set_peer(peer);
        }
        None
    }
}

/// This side's transport parameters start as configured.
impl<T: Choices, L, I> Build<T, L, layer::Connection, I>
    for LocalTransportParameters<TransportParameterSlots>
where
    for<'v> L: LineageLists<'v, T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        LocalTransportParameters::Configured(own_args::<T, L, I>(args).transport_parameters)
    }
}
impl<T: Choices, L> DataComponent<T, L, layer::Connection, ()>
    for LocalTransportParameters<TransportParameterSlots>
where
    for<'v> L: LineageLists<'v, T>,
{
}

/// The peer's transport parameters are not known when the connection is
/// made, even to a client that offers 0-RTT: the remembered ones are set
/// when its first ClientHello is written.
impl<T: Choices, L: ParametersOf<TransportParameterSpace>> Build<T, L, layer::Connection, ()>
    for PeerTransportParameters<TransportParameterSlots<L>>
where
    for<'v> L: LineageLists<'v, T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        PeerTransportParameters::NotYet
    }
}
impl<T: Choices, L: ParametersOf<TransportParameterSpace>>
    DataComponent<T, L, layer::Connection, ()>
    for PeerTransportParameters<TransportParameterSlots<L>>
where
    for<'v> L: LineageLists<'v, T>,
{
}

// ---- the entry of a logical link ----

/// The clone is moved from the request for the first link path over the
/// logical link.
impl<T: Choices, L> Build<T, L, layer::LinkEntry, ()> for LinkClone<T::Link>
where
    for<'v> L: LineageLists<'v, T>,
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
impl<T: Choices, L> DataComponent<T, L, layer::LinkEntry, ()> for LinkClone<T::Link> where
    for<'v> L: LineageLists<'v, T>
{
}

/// The first entry takes the facts the connection was made with; a later
/// one starts as the side says.
impl<T: Choices, L, I> Build<T, L, layer::LinkEntry, I> for LinkFacts
where
    for<'v> L: LineageLists<'v, T>,
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
impl<T: Choices, L> DataComponent<T, L, layer::LinkEntry, ()> for LinkFacts where
    for<'v> L: LineageLists<'v, T>
{
}

/// The limit starts with nothing received or sent, by the configured
/// factor.
impl<T: Choices, L, I> Build<T, L, layer::LinkEntry, I> for AntiAmplification
where
    for<'v> L: LineageLists<'v, T>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<AntiAmplificationFactor, I>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LinkEntry>,
        _: &mut ArgsOf<T, L, layer::LinkEntry>,
    ) -> Self {
        AntiAmplification::new(*parents.get::<AntiAmplificationFactor, I>())
    }
}
impl<T: Choices, L> DataComponent<T, L, layer::LinkEntry, ()> for AntiAmplification where
    for<'v> L: LineageLists<'v, T>
{
}

// ---- the link path ----

/// The connection's first link path is active from the start: the
/// handshake runs over it. A later one is a candidate until it is
/// validated.
impl<T: Choices, L, I> Build<T, L, layer::LinkPath, I> for LinkPathRole<InstantOf<T>>
where
    for<'v> L: LineageLists<'v, T>,
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
/// It reads itself, which other components change.
///
/// Not here yet: entering `Closing` and `Draining`, which read the record
/// of why the connection closed.
impl<T: Choices, L, I> DataComponent<T, L, layer::LinkPath, I> for LinkPathRole<InstantOf<T>>
where
    for<'v> L: LineageLists<'v, T>,
    for<'v> <L as LineageLists<'v, T>>::LinkPath: GetAt<LinkPathRole<InstantOf<T>>, I>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add::<LinkPathRole<InstantOf<T>>>();
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
}
