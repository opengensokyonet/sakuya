//! Reading and writing transport parameters as `nitori_call` operations.
//!
//! [`read_transport_parameters`] reads the whole value of the
//! `quic_transport_parameters` TLS extension, to the end of the source, into
//! the slots of the transport parameter types of a list of parts;
//! [`write_transport_parameters`] writes it. [`read_remembered_transport_parameters`]
//! reads the server's transport parameters stored with a session ticket and
//! keeps the ones remembered for 0-RTT. They are the operations of
//! [`parameters::codec`](crate::parameters::codec) for the space of the
//! transport parameters, where the context of a set of parameters is the
//! role of the endpoint that sends it. Each function is also an operation
//! struct with `{Name}Ext` on receiver accesses inside other operations and
//! `{Name}HostExt` on call executors, including the `sync_` methods for
//! receivers that never wait. The value of each parameter type is read and
//! written by the operations in the `codec` module of the type.
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{
    RememberedForZeroRtt, ServerOnlyError, TransportParameterAttributes, TransportParameterList,
    TransportParameterSlots, TransportParameterSpace, TransportParameterValueErrors,
    TransportParameters,
};
use crate::{
    parameters::{
        ParameterList, ParameterSpace, Parameters, ParametersOf,
        codec::{ReadParametersError, WriteParametersError, read_parameters, write_parameters},
    },
    parts::HList,
    v1::{role::Role, transport_error::TransportErrorCode},
};
use bytes::Buf;
use core::marker::PhantomData;
use nitori_call::{ReceiverAccess, call};
use nitori_io::prelude::*;

/// Failures that [`read_transport_parameters`] can produce, for the list of
/// parts `Ps`, of version 1 alone unless a list is given.
///
/// Every failure corresponds to the transport error
/// TRANSPORT_PARAMETER_ERROR
/// ([`transport_error_code`](ReadParametersError::transport_error_code)).
pub type ReadTransportParametersError<E, Ps = HList![crate::v1::Part]> =
    ReadParametersError<E, ServerOnlyError, TransportParameterValueErrors<Ps>>;

/// Failures that [`write_transport_parameters`] can produce.
pub type WriteTransportParametersError<E> = WriteParametersError<E, ServerOnlyError>;

/// Reads the transport parameters that an endpoint in role `sender` sent,
/// the whole source, into the slots of the transport parameter types of the
/// list of parts `Ps`, which `parts` names.
///
/// A parameter that no part of `Ps` defines is kept as an unknown
/// parameter, including the parameters of an extension that is not in `Ps`
/// and reserved parameters; its value is a chunk of the source.
///
/// # Errors
///
/// [`ReadParametersError::Id`], [`ReadParametersError::Length`] or
/// [`ReadParametersError::Value`] if the source ends within a parameter;
/// [`ReadParametersError::Duplicate`] for a parameter that appears twice;
/// [`ReadParametersError::NotAdmitted`] for a parameter that a client sent
/// but only a server may send; and [`ReadParametersError::InvalidValue`]
/// for a value that its parameter type rejects.
///
/// # Panics
///
/// If the receiver returns a chunk longer than requested, which breaks the
/// `ReadChunk` contract of `nitori_io`; see [`payload`](crate::payload).
#[call(sync)]
pub async fn read_transport_parameters<Ps, F, A>(
    io: &mut A,
    sender: Role,
    parts: PhantomData<Ps>,
) -> Result<TransportParameters<F::Chunk, Ps>, ReadTransportParametersError<F::Error, Ps>>
where
    Ps: ParametersOf<TransportParameterSpace>,
    F: ReadChunk<Chunk: Default + Unpin>,
    A: ReceiverAccess<Family = F>,
{
    let PhantomData = parts;
    read_parameters(
        io,
        sender,
        PhantomData::<(TransportParameterSpace, TransportParameterList<Ps>)>,
    )
    .await
}

/// Reads the server's transport parameters stored with a session ticket,
/// the whole source, as [`read_transport_parameters`] reads the parameters
/// a server sent, and keeps the slots of the types remembered for 0-RTT
/// ([RFC 9000 §7.4.1]): those whose storing is mandatory or optional
/// ([`RememberedForZeroRtt`](super::RememberedForZeroRtt)).
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
/// # Panics
///
/// If the receiver returns a chunk longer than requested, which breaks the
/// `ReadChunk` contract of `nitori_io`; see [`payload`](crate::payload).
///
/// [RFC 9000 §7.4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4.1
#[call(sync)]
pub async fn read_remembered_transport_parameters<Ps, F, A>(
    io: &mut A,
    parts: PhantomData<Ps>,
) -> Result<TransportParameterSlots<Ps>, ReadTransportParametersError<F::Error, Ps>>
where
    Ps: ParametersOf<TransportParameterSpace>,
    F: ReadChunk<Chunk: Default + Unpin>,
    A: ReceiverAccess<Family = F>,
{
    let mut parameters = read_transport_parameters(io, Role::Server, parts).await?;
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

impl<E, C> ReadParametersError<E, ServerOnlyError, C> {
    /// The transport error the failure corresponds to: always
    /// TRANSPORT_PARAMETER_ERROR ([RFC 9000 §7.4]), the error of
    /// [`TransportParameterSpace`].
    ///
    /// [RFC 9000 §7.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4
    pub fn transport_error_code(&self) -> TransportErrorCode {
        TransportParameterSpace::ERROR_CODE
    }
}

/// Writes `parameters`, the slots of the list of transport parameter types
/// `L` and the unknown parameters, as an endpoint in role `sender` sends
/// them, after checking them with [`Parameters::validate`].
///
/// The slots that hold a parameter are written in the order of the list,
/// including a parameter that has the default value of its type; the
/// unknown parameters follow in their order. Acceptance by the receiver
/// does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteParametersError::Invalid`] before writing anything, and
/// [`WriteParametersError::Write`] if the receiver stops accepting bytes or
/// fails; bytes accepted before stay written, and the error counts them
/// over the whole encoding.
#[call(sync)]
pub async fn write_transport_parameters<L, D, F, A>(
    io: &mut A,
    parameters: Parameters<TransportParameterSpace, L, D>,
    sender: Role,
) -> Result<(), WriteTransportParametersError<F::Error>>
where
    L: ParameterList<TransportParameterSpace>,
    D: Buf,
    F: Write,
    A: ReceiverAccess<Family = F>,
{
    write_parameters(io, parameters, sender).await
}
