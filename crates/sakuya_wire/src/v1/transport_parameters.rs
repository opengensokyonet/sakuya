//! QUIC transport parameters ([RFC 9000 §18]).
//!
//! Each endpoint states its transport parameters once, in the TLS handshake:
//! a sequence of parameters, each an ID and a length, both variable-length
//! integers, followed by that many bytes of value. They are a parameter
//! space of [`parameters`](crate::parameters), [`TransportParameterSpace`]:
//! each parameter is a type of its own that is the value of its ID, and the
//! parameters of an endpoint are a slot for each type of the parts that the
//! endpoint uses, with the parameters that no type claims kept as
//! [`UnknownParameter`](crate::parameters::UnknownParameter)s.
//!
//! This module holds the space and the 17 parameter types that QUIC version
//! 1 defines ([RFC 9000 §18.2]), which are the parameter types of
//! [`v1::Part`](crate::v1::Part):
//!
//! - [`integer`]: the parameters whose value is one variable-length integer,
//!   such as [`integer::InitialMaxData`] and [`integer::MaxUdpPayloadSize`];
//! - [`connection_id`]: the parameters whose value is a connection ID;
//! - [`stateless_reset_token`], [`disable_active_migration`] and
//!   [`preferred_address`]: one parameter each.
//!
//! An extension defines its parameter types in its own module, for this
//! space, and they are the parameter types of its part. [`TransportParameters`]
//! names the parameters of a list of parts, of version 1 alone unless a list
//! is given. A slot is `None` for a parameter that is absent; a type that
//! [RFC 9000 §18.2] gives a default value implements [`Default`] with it,
//! and [`get_or_default`](crate::parameters::Parameters::get_or_default)
//! gives the value to use.
//!
//! [`codec::read_transport_parameters`] and
//! [`codec::write_transport_parameters`] take the [`Role`] of the endpoint
//! that sends the parameters, since a client must not send the parameters
//! that only a server may send ([`SentBy`]). Each parameter type checks the
//! rules of its own value, and a parameter that appears twice is rejected.
//! Whether the connection ID parameters match the connection IDs that the
//! packets used ([RFC 9000 §7.3]), and whether the ones that must be present
//! are, is for the handshake to check. Every failure of reading corresponds
//! to TRANSPORT_PARAMETER_ERROR.
//!
//! ```
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     parts::HList,
//!     v1::{
//!         self,
//!         role::Role,
//!         stream_count::StreamCount,
//!         transport_parameters::{
//!             TransportParameters,
//!             codec::{ReadTransportParametersHostExt as _, WriteTransportParametersHostExt as _},
//!             integer::{InitialMaxData, InitialMaxStreamsBidi, MaxUdpPayloadSize},
//!         },
//!     },
//!     var_int::VarInt,
//! };
//!
//! let mut parameters = TransportParameters::<&[u8]>::new();
//! parameters.set(InitialMaxData::new(VarInt::from(1_048_576u32)));
//! parameters.set(InitialMaxStreamsBidi::new(StreamCount::new(100).unwrap()));
//!
//! let mut encoding = Vec::new();
//! encoding
//!     .sync_write_transport_parameters_unpin(parameters.clone(), Role::Client)
//!     .unwrap();
//! assert_eq!(encoding.len(), parameters.encoded_len());
//!
//! let decoded = encoding
//!     .as_slice()
//!     .sync_read_transport_parameters_unpin(Role::Client, PhantomData::<HList![v1::Part]>)
//!     .unwrap();
//! assert_eq!(decoded, parameters);
//! assert_eq!(decoded.get::<InitialMaxData, _>().unwrap().get(), VarInt::from(1_048_576u32));
//! // `max_udp_payload_size` is absent, and its default is 65527.
//! assert!(decoded.get::<MaxUdpPayloadSize, _>().is_none());
//! let size: MaxUdpPayloadSize = decoded.get_or_default();
//! assert_eq!(size.get(), VarInt::from(65527u16));
//! ```
//!
//! [RFC 9000 §18]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
//! [RFC 9000 §7.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3
use crate::{
    parameters::{
        InvalidParametersError, ParameterList, ParameterSpace, Parameters, ParametersOf,
        ParametersPart, ReservedIds,
    },
    parts::HList,
    v1::{role::Role, transport_error::TransportErrorCode},
    var_int::VarInt,
};
use core::num::NonZeroU64;
use snafu::Snafu;

pub mod codec;
pub mod connection_id;
pub mod disable_active_migration;
pub mod integer;
pub mod preferred_address;
pub mod stateless_reset_token;

#[cfg(test)]
mod tests;

/// The parameter space of the QUIC transport parameters ([RFC 9000 §18]).
///
/// Each parameter type states who may send it ([`SentBy`]), and a set of
/// parameters is read or checked with the [`Role`] of the endpoint that
/// sends it: a parameter that only a server may send is not admitted from a
/// client ([`ServerOnlyError`]). The IDs of the form 31 × N + 27 are reserved
/// ([RFC 9000 §18.1]), and every failure of reading corresponds to
/// TRANSPORT_PARAMETER_ERROR ([RFC 9000 §7.4]).
///
/// [RFC 9000 §18]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18
/// [RFC 9000 §18.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1
/// [RFC 9000 §7.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TransportParameterSpace;

impl ParameterSpace for TransportParameterSpace {
    type Attributes = SentBy;
    type Context = Role;
    type AdmitError = ServerOnlyError;
    type ErrorCode = TransportErrorCode;

    const ERROR_CODE: TransportErrorCode = TransportErrorCode::TRANSPORT_PARAMETER_ERROR;

    const RESERVED: ReservedIds = ReservedIds::new(NonZeroU64::new(31).unwrap(), 27);

    /// `sender` is the role of the endpoint that sends the parameters.
    fn admit(_id: VarInt, sent_by: &SentBy, sender: Role) -> Result<(), ServerOnlyError> {
        match (sent_by, sender) {
            (SentBy::ServerOnly, Role::Client) => Err(ServerOnlyError),
            (SentBy::ServerOnly, Role::Server) | (SentBy::Either, _) => Ok(()),
        }
    }
}

/// Who may send a transport parameter ([RFC 9000 §18.2]): what
/// [`TransportParameterSpace`] attaches to each parameter type.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SentBy {
    /// A client or a server.
    Either,
    /// A server only: a server that receives the parameter treats it as a
    /// TRANSPORT_PARAMETER_ERROR.
    ServerOnly,
}

/// A client sends a transport parameter that only a server may send
/// ([RFC 9000 §18.2]).
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("only a server may send this transport parameter"))]
pub struct ServerOnlyError;

/// The transport parameter types of the list of parts `Ps`, such as
/// `HList![v1::Part, datagram::Part]`: one flat list, the parameter types
/// of each part in the order of the parts.
pub type TransportParameterList<Ps> = <Ps as ParametersOf<TransportParameterSpace>>::Parameters;

/// The transport parameters of one endpoint: a slot for each transport
/// parameter type of the list of parts `Ps`, of version 1 alone unless a
/// list is given, and the parameters that none of them claims.
///
/// `D` holds the values of unknown parameters: the chunk type of the source
/// for parameters that were read, any `Buf` for parameters to write.
pub type TransportParameters<D, Ps = HList![super::Part]> =
    Parameters<TransportParameterSpace, TransportParameterList<Ps>, D>;

/// The slots of the transport parameter types of the list of parts `Ps`,
/// of version 1 alone unless a list is given: the type of
/// [`Parameters::known`]. With `sculpt`, the slots of the parts of a list
/// are taken out of the slots of a longer list at once.
pub type TransportParameterSlots<Ps = HList![super::Part]> =
    <TransportParameterList<Ps> as ParameterList<TransportParameterSpace>>::Slots;

/// Transport parameters that must not be written
/// ([`Parameters::validate`]).
pub type InvalidTransportParametersError = InvalidParametersError<ServerOnlyError>;

/// The sum of the failures of reading the value of each transport parameter
/// type of the list of parts `Ps`.
pub type TransportParameterValueErrors<Ps = HList![super::Part]> =
    <TransportParameterList<Ps> as ParameterList<TransportParameterSpace>>::ValueErrors;

/// The 17 transport parameters of [RFC 9000 §18.2], in the order of their
/// IDs, `0x00` to `0x10`.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
impl ParametersPart<TransportParameterSpace> for super::Part {
    type Parameters = HList![
        connection_id::OriginalDestinationConnectionId,
        integer::MaxIdleTimeout,
        stateless_reset_token::StatelessResetToken,
        integer::MaxUdpPayloadSize,
        integer::InitialMaxData,
        integer::InitialMaxStreamDataBidiLocal,
        integer::InitialMaxStreamDataBidiRemote,
        integer::InitialMaxStreamDataUni,
        integer::InitialMaxStreamsBidi,
        integer::InitialMaxStreamsUni,
        integer::AckDelayExponent,
        integer::MaxAckDelay,
        disable_active_migration::DisableActiveMigration,
        preferred_address::PreferredAddress,
        integer::ActiveConnectionIdLimit,
        connection_id::InitialSourceConnectionId,
        connection_id::RetrySourceConnectionId,
    ];
}

crate::assert_parameters_distinct!(
    TransportParameterSpace,
    TransportParameterList<HList![super::Part]>
);

/// A reserved transport parameter ID: one of the form 31 × N + 27
/// ([RFC 9000 §18.1]).
///
/// These IDs are never assigned to a parameter, and an endpoint that
/// receives one ignores it; an endpoint sends one to check that its peer
/// does. No parameter type claims such an ID, so a parameter with one is an
/// [`UnknownParameter`](crate::parameters::UnknownParameter), whose ID this
/// converts into.
///
/// [RFC 9000 §18.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReservedParameterId(VarInt);

impl ReservedParameterId {
    /// The ID `id`.
    ///
    /// # Errors
    ///
    /// [`UnreservedParameterIdError`] if `id` is not reserved.
    pub const fn new(id: VarInt) -> Result<Self, UnreservedParameterIdError> {
        if TransportParameterSpace::RESERVED.contains(id) {
            Ok(Self(id))
        } else {
            Err(UnreservedParameterIdError { id })
        }
    }

    /// The parameter ID.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<ReservedParameterId> for VarInt {
    fn from(id: ReservedParameterId) -> Self {
        id.0
    }
}

impl TryFrom<VarInt> for ReservedParameterId {
    type Error = UnreservedParameterIdError;

    fn try_from(id: VarInt) -> Result<Self, Self::Error> {
        Self::new(id)
    }
}

/// A transport parameter ID is not reserved: not of the form 31 × N + 27.
///
/// It is constructed only when the check fails, so the ID it holds is never
/// reserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("transport parameter ID {:#x} is not of the form 31 * N + 27", id.get()))]
pub struct UnreservedParameterIdError {
    id: VarInt,
}

impl UnreservedParameterIdError {
    /// The ID, which is not reserved.
    pub const fn id(self) -> VarInt {
        self.id
    }
}
