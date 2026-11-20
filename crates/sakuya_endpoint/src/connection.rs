//! What `accept` and `start` share: registering the first local
//! connection ID, making the issuer of the later ones and making the
//! connection.

use sakuya_connection::{
    composition::Composition,
    driver::LendNode,
    error::ConnectionErrorsOf,
    layer::{LinkPathArgs, LogicalPathArgs},
    role::LinkPathRole,
    share::SoleLogicalPath,
    shared::DrivenFromOutside,
    v1::{
        self,
        connection_ids::{FirstLocalConnectionId, LocalConnectionIdIssuer},
    },
};
use sakuya_datagram_routing::route::{
    association::MatchAssociation, recognizer::ConnectionIdGenerator,
};
use sakuya_link::Link as _;
use sakuya_wire::connection_id::NonEmptyCid;

use std::sync::Arc;

use crate::{
    choices::{
        ConnectionDatagramReceiver, EndpointChoices, FirstLocalRegistration, LinkOf,
        RegistrationOf, ZeroLengthOccupancyOf,
    },
    domain::Domain,
    endpoint::EndpointClosedError,
    issuer::EndpointConnectionIdIssuer,
    part::{ConnectionFacts, ConnectionPartsOf, CoreFacts, PartConfigs},
    role::EndpointPartList,
    zero_length::ZeroLengthRegistration,
};

/// The first local connection ID of a connection, as
/// [`register_first_local`] registered it, with what issues the later
/// ones.
pub(crate) struct RegisteredFirstLocal<E: EndpointChoices> {
    /// The connection ID.
    pub(crate) id: FirstLocalConnectionId,
    /// The issuer, with the registration of a connection ID that is not
    /// empty, which the connection's local connection ID strategy keeps.
    pub(crate) issuer: LocalConnectionIdIssuer<EndpointConnectionIdIssuer<E>>,
}

/// Generates and registers the first local connection ID of a connection
/// over `link`, whose datagram receiver is `receiver`; with `zero_length`,
/// the connection uses zero-length local connection IDs on that local end.
/// The connection's generator, `generator` when given and otherwise one made
/// from the endpoint's configuration, generates it and goes into the issuer
/// of the later ones, which registers them for the same receiver.
///
/// The entry is registered before the connection ID is disclosed. The entry
/// of a connection ID that is not empty goes with the issuer, for the
/// connection's local connection ID strategy to keep; `receiver` keeps the
/// entry of a zero-length one, which is registered by the local end.
///
/// # Errors
///
/// [`EndpointClosedError`] once the endpoint has been closed; nothing is
/// registered then, and `zero_length` is left as it was.
pub(crate) fn register_first_local<E: EndpointChoices>(
    domain: &Arc<Domain<E>>,
    receiver: &mut ConnectionDatagramReceiver<E>,
    link: &LinkOf<E>,
    zero_length: &mut Option<ZeroLengthOccupancyOf<E>>,
    generator: Option<E::ConnectionIds>,
) -> Result<RegisteredFirstLocal<E>, EndpointClosedError> {
    if domain.is_closed() {
        return Err(EndpointClosedError);
    }
    let mut generator = generator.unwrap_or_else(|| E::ConnectionIds::new(&domain.connection_ids));
    let local = || MatchAssociation::ZeroCid(link.id().local.clone());
    let (id, registration): (_, Option<RegistrationOf<E>>) = match zero_length.take() {
        Some(occupancy) => {
            let registration = domain.register(local(), receiver);
            receiver.keep_first_local(FirstLocalRegistration::ZeroLength(
                ZeroLengthRegistration::new(registration, occupancy),
            ));
            (FirstLocalConnectionId::ZeroLength, None)
        }
        None => {
            let (cid, reset_token) = generator.generate();
            match NonEmptyCid::new(cid) {
                Ok(id) => {
                    let registration = domain.register(MatchAssociation::LocalCid(id), receiver);
                    (
                        FirstLocalConnectionId::Issued { id, reset_token },
                        Some(registration),
                    )
                }
                // A generator of zero-length connection IDs: the connection
                // is told apart by its local end.
                Err(_) => {
                    let registration = domain.register(local(), receiver);
                    receiver.keep_first_local(FirstLocalRegistration::Issued(registration));
                    (FirstLocalConnectionId::ZeroLength, None)
                }
            }
        }
    };
    let issuer = EndpointConnectionIdIssuer::new(Arc::clone(domain), generator, receiver.poster());
    Ok(RegisteredFirstLocal {
        id,
        issuer: LocalConnectionIdIssuer::new(issuer, registration),
    })
}

/// The connection of the choices `T` and the list of parts the endpoint's
/// list of parts `EL` stands for, made from the configurations of its parts
/// and the facts `core`, with its first link path over `link`: what the
/// host wraps and drives, and takes the application's handles from.
pub(crate) fn make_connection<T, EL, C>(
    clock: T::Clock,
    configs: <EL as PartConfigs<T, ConnectionPartsOf<EL>>>::Configs,
    core: CoreFacts<T>,
    link: T::Link,
) -> impl DrivenFromOutside + LendNode<T, ConnectionPartsOf<EL>> + 'static
where
    T: v1::Choices,
    EL: EndpointPartList<T>,
    ConnectionPartsOf<EL>: ConnectionErrorsOf,
    for<'v> ConnectionPartsOf<EL>: sakuya_connection::share::LineageLists<'v, T>,
    C: Composition<T, ConnectionPartsOf<EL>>,
{
    let mut facts = ConnectionFacts::new(core);
    let args = EL::connection_args(configs, &mut facts);
    let (driver, _) = C::connection(
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
    );
    driver
}
