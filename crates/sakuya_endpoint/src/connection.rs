//! What `accept` and `start` share: registering the first local
//! connection ID and making the connection.

use sakuya_connection::{
    layer::{Connection, LinkPathArgs, LogicalPathArgs},
    role::LinkPathRole,
    share::{LayerShares, LogicalPathKeys, SoleLogicalPath},
    v1::{self, connection_ids::FirstLocalConnectionId},
};
use sakuya_datagram_routing::route::{
    association::MatchAssociation, recognizer::ConnectionIdGenerator,
};
use sakuya_link::Link as _;
use sakuya_wire::connection_id::NonEmptyCid;

use crate::{
    choices::{
        ConnectionDatagramReceiver, EndpointChoices, FirstLocalRegistration, LinkOf, LocalOf,
    },
    domain::Domain,
    endpoint::EndpointClosedError,
    make::MakeConnection,
    part::{ConnectionFacts, CoreFacts, PartConfigs},
    zero_length::{ZeroLengthLocalOccupancy, ZeroLengthRegistration},
};

/// Generates and registers the first local connection ID of a connection
/// over `link`, whose entry `receiver` keeps; with `zero_length`, the
/// connection uses zero-length local connection IDs on that local end.
///
/// The entry is registered before the connection ID is disclosed.
///
/// # Errors
///
/// [`EndpointClosedError`] once the endpoint has been closed; nothing is
/// registered then.
pub(crate) fn register_first_local<E: EndpointChoices>(
    domain: &Domain<E>,
    receiver: &mut ConnectionDatagramReceiver<E>,
    link: &LinkOf<E>,
    zero_length: Option<ZeroLengthLocalOccupancy<LocalOf<E>>>,
) -> Result<FirstLocalConnectionId, EndpointClosedError> {
    if domain.is_closed() {
        return Err(EndpointClosedError);
    }
    let local = || MatchAssociation::ZeroCid(link.id().local.clone());
    if let Some(occupancy) = zero_length {
        let registration = domain.register(local(), receiver);
        receiver.keep_first_local(FirstLocalRegistration::ZeroLength(
            ZeroLengthRegistration::new(registration, occupancy),
        ));
        return Ok(FirstLocalConnectionId::ZeroLength);
    }
    let mut generator = E::ConnectionIds::new(&domain.connection_ids);
    let (cid, reset_token) = generator.generate();
    match NonEmptyCid::new(cid) {
        Ok(id) => {
            let registration = domain.register(MatchAssociation::LocalCid(id), receiver);
            receiver.keep_first_local(FirstLocalRegistration::Issued(registration));
            Ok(FirstLocalConnectionId::Issued { id, reset_token })
        }
        // A generator of zero-length connection IDs: the connection is
        // told apart by its local end.
        Err(_) => {
            let registration = domain.register(local(), receiver);
            receiver.keep_first_local(FirstLocalRegistration::Issued(registration));
            Ok(FirstLocalConnectionId::ZeroLength)
        }
    }
}

/// The connection of the choices `T` and the list of parts `L`, made from
/// the configurations of its parts and the facts `core`, with its first
/// link path over `link`.
pub(crate) fn make_connection<T, L, D>(
    clock: T::Clock,
    configs: <L as PartConfigs<T, L>>::Configs,
    core: CoreFacts<T>,
    link: T::Link,
) -> D
where
    T: v1::Choices,
    L: PartConfigs<T, L>
        + LayerShares<T, L, Connection, Args = <L as PartConfigs<T, L>>::Args>
        + LogicalPathKeys<Key = SoleLogicalPath>,
    D: MakeConnection<T, L>,
{
    let mut facts = ConnectionFacts::new(core);
    let args = L::connection_args(configs, &mut facts);
    D::make(
        clock,
        args,
        LogicalPathArgs {
            path: SoleLogicalPath,
        },
        LinkPathArgs {
            path: SoleLogicalPath,
            link,
            role: LinkPathRole::Active,
            peer_switched_local_id: false,
        },
    )
}
