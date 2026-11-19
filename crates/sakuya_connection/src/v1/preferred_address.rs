//! The call that migrates a client to its server's preferred address (RFC
//! 9000 §9.6).
//!
//! [`preferred_address_migrating`] is the second call of each logical
//! path. A server has nothing for it to do, and drops it at once. A
//! client's waits until its handshake is confirmed (§9.6.1); if the
//! server's transport parameters of this connection have a
//! `preferred_address` and this side's connection ID is not zero-length,
//! it asks the migration policy which address to go to
//! ([`choose_preferred_address`](super::migration::MigrationPolicy::choose_preferred_address)),
//! and takes a link to it with the client's
//! [`LinkConnector`], beside the link
//! of the active link path, awaiting it in the call:
//!
//! - With the link, it asks for a `Candidate` link path over it, unless the
//!   connection is closing or the logical path has one there already. The
//!   candidate challenges the address as soon as it is built and only
//!   probes (§9.6.2, §21.5.3), with a connection ID of the server's never
//!   used before, which the preferred address's own, numbered 1, is
//!   (§9.6.1, §9.5). The switch to it waits for its validation, with a new
//!   recovery layer, as the server's address changes: once it is validated
//!   the client sends there and the former active link path settles; when
//!   validation fails the candidate ends and the client stays on the
//!   original address (MUST). The server's `disable_active_migration` does
//!   not stop it (§9).
//! - Without, the reason goes to the connection's events
//!   ([`preferred_address_connect_failed`](super::events::ConnectionEvents::preferred_address_connect_failed))
//!   and the policy is asked again, the address among those that failed;
//!   no address is tried twice.
//!
//! The call does nothing else, and ends once it asked for the candidate or
//! the policy chose no address.
//!
//! [`preferred_address_migrating`] is also the operation struct
//! [`PreferredAddressMigrating`], with `PreferredAddressMigratingExt` on
//! receiver accesses.
// `#[call]` generates a constructor and an extension trait without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use core::{
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    task::Poll,
};

use frunk_core::{HList, hlist_pat};
use nitori_call::{LentAccess, LentCall, ReceiverFamily, call};
use sakuya_link::{Link, LinkId};
use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::ParametersOf,
    parts::Selector,
    v1::{
        role::Role,
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace,
            preferred_address::{PreferredAddress, PreferredAddressFamilies},
        },
    },
};

use super::{
    Choices, CloseCauseOf, EventsOf, MigrationPolicyOf, Side,
    close::CloseReasonRecord,
    component_events::HandshakeConfirmed,
    confirmation::HandshakeConfirmation,
    connection_ids::ConnectionIdsOf,
    events::{ConnectionEventSink, ConnectionEvents},
    link::LinkClone,
    link_connector::{LinkConnector, OwnLinkConnector},
    migration::{
        MigrationPolicy, PreferredAddressContext, SwitchRecovery,
        rules::{ConnectionMigrationOf, LinkPathMigrationOf},
    },
    parameters::PeerTransportParameters,
};
use crate::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    clock::InstantOf,
    component::{ArgsOf, LineageOf, RequestOf},
    component_event::EventSubscriptions,
    error::ConnectionErrorsOf,
    layer::{LinkPathArgs, LogicalPath, NodeKey},
    request::StructureRequest,
    role::LinkPathRole,
    share::{FlatMut, LineageLists, LineagePartList, NodeData},
    take::{GetAt, TakeEach},
};

/// The connector of the links a side of the choices `T` takes.
type ConnectorOf<T> = <<<T as super::MakerChoices>::Side as Side>::Own as OwnLinkConnector<
    <T as crate::clock::ConnectionChoices>::Link,
>>::Connector;

/// What the call that migrates to a preferred address does with its view:
/// everything but waiting.
pub trait PreferredAddressMigratingCapability: ReceiverFamily {
    /// The link the connection uses.
    type Link: Link;
    /// Why no link was taken.
    type Error;
    /// The taking of one link, under way.
    type Connect: Future<Output = Result<Self::Link, Self::Error>>;
    /// A request of the connection's structure.
    type Request;

    /// The addresses of the server's preferred address, once the handshake
    /// is confirmed and this side may migrate there; `None` when it never
    /// will: a server, a client whose server gave none, with a zero-length
    /// connection ID of its own or without a connector, or a connection
    /// that is closing.
    fn offered<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
    ) -> Poll<Option<PreferredAddressFamilies>>
    where
        Self: 'v;

    /// The address the migration policy chooses of `offered`, with
    /// `failed` tried already, and the taking of a link to it beside the
    /// link of the active link path; `None` when the policy chooses none or
    /// no link path is active.
    fn connect<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        offered: &PreferredAddressFamilies,
        failed: &[SocketAddr],
    ) -> Option<(SocketAddr, Self::Connect)>
    where
        Self: 'v;

    /// `link` was taken: the request of the candidate over it, or `None`
    /// when the connection is closing or a link path over it is there.
    fn link_taken<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        link: Self::Link,
    ) -> Option<Self::Request>
    where
        Self: 'v;

    /// The candidate over `link` was built: the switch to it waits for its
    /// validation, with a new recovery layer.
    fn await_validation<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        link: &LinkId<<Self::Link as Link>::Local, <Self::Link as Link>::Peer>,
    ) where
        Self: 'v;

    /// No link to `address` was taken, for `error`.
    fn connect_failed<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        address: SocketAddr,
        error: &Self::Error,
    ) where
        Self: 'v;
}

/// The positions the call takes by: in the logical path's lineage, `Ihc` of
/// the confirmation, `Ipt` of the peer's transport parameters, `Ipa` of the
/// preferred address among them, `Icid` of the connection IDs, `Imig` of
/// the migration, `Iown` of the side's own data, `Ic` of the record of why
/// the connection closed and `Iev` of the events; `Ir` of a link path's
/// role, `Ilc` of an entry's clone of its link and `Ilm` of what migration
/// keeps in a link path.
type Positions<Ihc, Ipt, Ipa, Icid, Imig, Iown, Ic, Iev, Ir, Ilc, Ilm> =
    ((Ihc, Ipt, Ipa, Icid), (Imig, Iown, Ic, Iev), (Ir, Ilc, Ilm));

impl<T, L, K, B, Ihc, Ipt, Ipa, Icid, Imig, Iown, Ic, Iev, Ir, Ilc, Ilm>
    PreferredAddressMigratingCapability
    for NodeCallFamily<
        T,
        L,
        LogicalPath,
        K,
        Positions<Ihc, Ipt, Ipa, Icid, Imig, Iown, Ic, Iev, Ir, Ilc, Ilm>,
        B,
    >
where
    T: Choices,
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace> + ConnectionErrorsOf,
    B: CallBundle,
    TransportParameterSlots<L>: Selector<Option<PreferredAddress>, Ipa>,
    <T::Side as Side>::Own: OwnLinkConnector<T::Link>,
    MigrationPolicyOf<T>:
        MigrationPolicy<<T::Link as Link>::Local, <T::Link as Link>::Peer, InstantOf<T>>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<HandshakeConfirmation, Ihc>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + GetAt<ConnectionMigrationOf<T>, Imig>
        + GetAt<<T::Side as Side>::Own, Iown>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    for<'s> NodeData<T, L, crate::layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, crate::layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir> + TakeEach<'s, HList![LinkPathMigrationOf<T>], Ilm>,
    for<'s> NodeData<T, L, crate::layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, crate::layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ilc>,
{
    type Link = T::Link;
    type Error = <ConnectorOf<T> as LinkConnector<T::Link>>::Error;
    type Connect = <ConnectorOf<T> as LinkConnector<T::Link>>::Connect;
    type Request = RequestOf<T, L>;

    fn offered<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
    ) -> Poll<Option<PreferredAddressFamilies>>
    where
        Self: 'v,
    {
        let lineage = &view.get_mut().lineage;
        if <T::Side as Side>::ROLE != Role::Client {
            return Poll::Ready(None);
        }
        if *lineage.get::<HandshakeConfirmation, Ihc>() != HandshakeConfirmation::Confirmed {
            return Poll::Pending;
        }
        let closing = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .is_written();
        let zero_length = lineage.get::<ConnectionIdsOf<T>, Icid>().local() == ConnectionId::EMPTY;
        let connector = lineage
            .get::<<T::Side as Side>::Own, Iown>()
            .link_connector()
            .is_some();
        let offered = lineage
            .get::<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>()
            .known()
            .and_then(|slots| *Selector::<Option<PreferredAddress>, Ipa>::get(slots))
            .map(|preferred| preferred.addresses);
        Poll::Ready(offered.filter(|_| !closing && !zero_length && connector))
    }

    fn connect<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        offered: &PreferredAddressFamilies,
        failed: &[SocketAddr],
    ) -> Option<(SocketAddr, Self::Connect)>
    where
        Self: 'v,
    {
        let loan = view.get_mut();
        let address = loan
            .lineage
            .get_mut::<ConnectionMigrationOf<T>, Imig>()
            .policy_mut()
            .choose_preferred_address(&PreferredAddressContext { offered, failed })?;
        let NodeKey::LogicalPath(path) = loan.others.here().clone() else {
            unreachable!("a logical path's lend carries its key")
        };
        let mut active = None;
        loan.others
            .each_link_path_read::<LinkPathRole<InstantOf<T>>, Ir>(|key, role| {
                if *role == LinkPathRole::Active
                    && let NodeKey::LinkPath(each, over) = key
                    && *each == path
                {
                    active = Some(over.clone());
                }
            });
        let hlist_pat![beside] = loan
            .others
            .link_entry::<HList![LinkClone<T::Link>], Ilc>(&active?)?;
        let beside = beside.0.clone();
        let own = loan.lineage.get::<<T::Side as Side>::Own, Iown>();
        let connect = own.link_connector()?.connect_beside(&beside, address);
        Some((address, connect))
    }

    fn link_taken<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        link: T::Link,
    ) -> Option<RequestOf<T, L>>
    where
        Self: 'v,
    {
        let loan = view.get_mut();
        if loan
            .lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .is_written()
        {
            return None;
        }
        let NodeKey::LogicalPath(path) = loan.others.here().clone() else {
            unreachable!("a logical path's lend carries its key")
        };
        let there = loan.others.link_path_keys().any(|key| {
            matches!(key, NodeKey::LinkPath(each, over) if *each == path && over == link.id())
        });
        if there {
            return None;
        }
        Some(StructureRequest::AddLinkPath {
            args: LinkPathArgs {
                path,
                link,
                role: LinkPathRole::Candidate,
                // a new server address: no connection ID is kept towards it
                // (RFC 9000 §9.5)
                peer_switched_local_id: true,
            },
        })
    }

    fn await_validation<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        link: &LinkId<<T::Link as Link>::Local, <T::Link as Link>::Peer>,
    ) where
        Self: 'v,
    {
        let loan = view.get_mut();
        let NodeKey::LogicalPath(path) = loan.others.here().clone() else {
            unreachable!("a logical path's lend carries its key")
        };
        if let Some(hlist_pat![mut migration]) = loan
            .others
            .link_path::<HList![LinkPathMigrationOf<T>], Ilm>(&path, link)
        {
            migration.await_validation(SwitchRecovery::New);
        }
    }

    fn connect_failed<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        address: SocketAddr,
        error: &Self::Error,
    ) where
        Self: 'v,
    {
        if !<EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED {
            return;
        }
        let loan = view.get_mut();
        let now = loan.others.now();
        if let Some(events) = loan
            .lineage
            .get_mut::<ConnectionEventSink<EventsOf<T, L>>, Iev>()
            .active::<InstantOf<T>>()
        {
            events.preferred_address_connect_failed(now, address, error);
        }
    }
}

/// The call that migrates a client to its server's preferred address; what
/// it does is in the [module documentation](self).
#[call(yields = W::Request)]
pub async fn preferred_address_migrating<W: PreferredAddressMigratingCapability>(
    host: &mut impl LentAccess<Family = W>,
) {
    let offered = poll_fn(|_| host.with(|mut view| W::offered(view.as_pin()))).await;
    let Some(offered) = offered else {
        return;
    };
    let mut failed = Vec::new();
    while let Some((address, connect)) =
        host.with(|mut view| W::connect(view.as_pin(), &offered, &failed))
    {
        match connect.await {
            Ok(link) => {
                let id = link.id().clone();
                if let Some(request) = host.with(|mut view| W::link_taken(view.as_pin(), link)) {
                    yield request;
                    host.with(|mut view| W::await_validation(view.as_pin(), &id));
                }
                return;
            }
            Err(error) => {
                host.with(|mut view| W::connect_failed(view.as_pin(), address, &error));
                failed.push(address);
            }
        }
    }
}

/// The kind of the call that migrates a client to its server's preferred
/// address. It subscribes to the handshake confirmed, which it waits for;
/// a server's is not needed.
#[derive(Debug)]
pub struct PreferredAddressMigratingKind;

impl<T, L, Ihc, Ipt, Ipa, Icid, Imig, Iown, Ic, Iev, Ir, Ilc, Ilm>
    CallKind<T, L, LogicalPath, Positions<Ihc, Ipt, Ipa, Icid, Imig, Iown, Ic, Iev, Ir, Ilc, Ilm>>
    for PreferredAddressMigratingKind
where
    T: Choices,
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace> + ConnectionErrorsOf,
    TransportParameterSlots<L>: Selector<Option<PreferredAddress>, Ipa>,
    <T::Side as Side>::Own: OwnLinkConnector<T::Link>,
    MigrationPolicyOf<T>:
        MigrationPolicy<<T::Link as Link>::Local, <T::Link as Link>::Peer, InstantOf<T>>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<HandshakeConfirmation, Ihc>
        + GetAt<PeerTransportParameters<TransportParameterSlots<L>>, Ipt>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + GetAt<ConnectionMigrationOf<T>, Imig>
        + GetAt<<T::Side as Side>::Own, Iown>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    for<'s> NodeData<T, L, crate::layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, crate::layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir> + TakeEach<'s, HList![LinkPathMigrationOf<T>], Ilm>,
    for<'s> NodeData<T, L, crate::layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, crate::layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ilc>,
    Ihc: 'static,
    Ipt: 'static,
    Ipa: 'static,
    Icid: 'static,
    Imig: 'static,
    Iown: 'static,
    Ic: 'static,
    Iev: 'static,
    Ir: 'static,
    Ilc: 'static,
    Ilm: 'static,
{
    type Call<B: CallBundle> = LentCall<
        NodeCallFamily<
            T,
            L,
            LogicalPath,
            PreferredAddressMigratingKind,
            Positions<Ihc, Ipt, Ipa, Icid, Imig, Iown, Ic, Iev, Ir, Ilc, Ilm>,
            B,
        >,
        PreferredAddressMigrating,
    >;
    fn start<B: CallBundle>(_: &mut ArgsOf<T, L, LogicalPath>) -> Self::Call<B> {
        LentCall::new(PreferredAddressMigrating::new())
    }
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<HandshakeConfirmed>();
    }
    /// A server never migrates to a preferred address.
    fn no_longer_needed<'v>(_: &LineageOf<'v, T, L, LogicalPath>) -> bool {
        <T::Side as Side>::ROLE != Role::Client
    }
}
