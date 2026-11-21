//! Reading and writing transport parameters.
//!
//! [`read_transport_parameters`] reads the whole value of the
//! `quic_transport_parameters` TLS extension, to the end of the source, into
//! the slots of the transport parameter types of a list of parts;
//! [`write_transport_parameters`] writes it. [`read_remembered_transport_parameters`]
//! reads the server's transport parameters stored with a session ticket and
//! keeps the ones remembered for 0-RTT. They are the functions of
//! [`parameters::codec`](crate::parameters::codec) for the space of the
//! transport parameters, where the context of a set of parameters is the
//! role of the endpoint that sends it. The value of each parameter type is
//! read and written by the functions in the `codec` module of the type.
use super::{
    RememberedForZeroRtt, ServerOnlyError, TransportParameterAttributes, TransportParameterList,
    TransportParameterSlots, TransportParameterSpace, TransportParameterValueErrors,
    TransportParameters,
};
use crate::parameters::{
    ParameterList, Parameters, ParametersOf,
    codec::{ReadParametersError, read_parameters, write_parameters},
};
use crate::{role::Role, transport_parameters::InvalidTransportParametersError};
use bytes::{Buf, BufMut};
use core::marker::PhantomData;
use nitori_io::SplitTo;
use sakuya_wire::parts::HList;

/// Failures that [`read_transport_parameters`] can produce, for the list of
/// parts `Ps`, of version 1 alone unless a list is given.
///
/// Every failure corresponds to the transport error
/// TRANSPORT_PARAMETER_ERROR
/// ([`TransportParameterSpace::ERROR_CODE`](crate::parameters::ParameterSpace::ERROR_CODE)).
pub type ReadTransportParametersError<Ps = HList![crate::Part]> =
    ReadParametersError<ServerOnlyError, TransportParameterValueErrors<Ps>>;

/// Reads the transport parameters that an endpoint in role `sender` sent,
/// the whole source, into the slots of the transport parameter types of the
/// list of parts `Ps`, which `parts` names.
///
/// A parameter that no part of `Ps` defines is kept as an unknown
/// parameter, including the parameters of an extension that is not in `Ps`
/// and reserved parameters; its value is a piece of the source.
///
/// # Errors
///
/// [`ReadParametersError::Id`], [`ReadParametersError::Length`] or
/// [`ReadParametersError::Value`] if the source ends within a parameter;
/// [`ReadParametersError::Duplicate`] for a parameter that appears twice;
/// [`ReadParametersError::NotAdmitted`] for a parameter that a client sent
/// but only a server may send; and [`ReadParametersError::InvalidValue`]
/// for a value that its parameter type rejects.
pub fn read_transport_parameters<Ps, S>(
    src: &mut S,
    sender: Role,
    parts: PhantomData<Ps>,
) -> Result<TransportParameters<S, Ps>, ReadTransportParametersError<Ps>>
where
    Ps: ParametersOf<TransportParameterSpace>,
    S: Buf + SplitTo,
{
    let PhantomData = parts;
    read_parameters(
        src,
        sender,
        PhantomData::<(TransportParameterSpace, TransportParameterList<Ps>)>,
    )
}

/// Reads the server's transport parameters stored with a session ticket,
/// the whole source, as [`read_transport_parameters`] reads the parameters
/// a server sent, and keeps the slots of the types remembered for 0-RTT
/// ([RFC 9000 §7.4.1]): those whose storing is mandatory or optional
/// ([`RememberedForZeroRtt`]).
///
/// Both endpoints store the encoding of the server's parameters as a
/// whole, the client the parameters it received and the server the ones it
/// sent, and read them back with this when 0-RTT is attempted. The slots of
/// the other types are empty, and unknown parameters are left out: they
/// are not remembered, and a client need not store a parameter it cannot
/// process.
///
/// # Errors
///
/// The failures of [`read_transport_parameters`] for parameters a server
/// sent; a parameter that is not remembered is checked like any other.
///
/// [RFC 9000 §7.4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4.1
pub fn read_remembered_transport_parameters<Ps, S>(
    src: &mut S,
    parts: PhantomData<Ps>,
) -> Result<TransportParameterSlots<Ps>, ReadTransportParametersError<Ps>>
where
    Ps: ParametersOf<TransportParameterSpace>,
    S: Buf + SplitTo,
{
    let mut parameters = read_transport_parameters(src, Role::Server, parts)?;
    TransportParameterList::<Ps>::retain(
        &mut parameters.known,
        &mut |attributes: &TransportParameterAttributes| {
            !matches!(
                attributes.remembered_for_zero_rtt,
                RememberedForZeroRtt::Prohibited
            )
        },
    );
    Ok(parameters.known)
}

/// Writes `parameters`, the slots of the list of transport parameter types
/// `L` and the unknown parameters, as an endpoint in role `sender` sends
/// them, after checking them with [`Parameters::validate`].
///
/// The slots that hold a parameter are written in the order of the list,
/// including a parameter that has the default value of its type; the
/// unknown parameters follow in their order.
///
/// # Errors
///
/// [`InvalidTransportParametersError`] if the parameters must not be
/// written; the check comes first, so nothing is written then.
///
/// # Panics
///
/// If `dst` has no room for the parameters, as [`BufMut`] does.
pub fn write_transport_parameters<L, D>(
    dst: &mut impl BufMut,
    parameters: Parameters<TransportParameterSpace, L, D>,
    sender: Role,
) -> Result<(), InvalidTransportParametersError>
where
    L: ParameterList<TransportParameterSpace>,
    D: Buf,
{
    write_parameters(dst, parameters, sender)
}
