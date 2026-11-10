//! Reading and writing a set of parameters as `nitori_call` operations.
//!
//! [`read_parameters`] reads a sequence of parameters to the end of its
//! source into the slots of a list of parameter types, and
//! [`write_parameters`] writes it; the
//! [module documentation](super#reading-and-writing) describes both. Each
//! function is also an operation struct, [`ReadParameters`] and
//! [`WriteParameters`], with `{Name}Ext` on receiver accesses inside other
//! operations and `{Name}HostExt` on call executors, including the `sync_`
//! methods for receivers that never wait. Constructing an operation performs
//! no IO.
//!
//! A space has operations of its own that name it, such as
//! [`read_transport_parameters`](crate::v1::transport_parameters::codec::read_transport_parameters),
//! which run these.
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{
    DuplicateError, InvalidParametersError, KeyedParameter, NotAdmittedError, ParameterList,
    ParameterSpace, Parameters, UnknownParameter, item_head, put,
};
use crate::{
    parts::{Coproduct, ErrorCoproduct, PartsError},
    payload::{ReadPayloadError, read_payload},
    var_int::{
        VarInt,
        codec::{ReadVarIntError, ReadVarIntExt as _},
    },
};
use bytes::Buf;
use core::marker::PhantomData;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{calls::WriteAllError, prelude::*};
use snafu::{IntoError, ResultExt, Snafu};

/// Reads the parameters of the list `L` in the space `S`, which `list`
/// names, from a set of parameters with `context`: the whole source.
///
/// Values of unknown parameters are chunks of the source.
///
/// # Errors
///
/// [`ReadParametersError::Id`], [`ReadParametersError::Length`] or
/// [`ReadParametersError::Value`] if the source ends within a parameter or
/// fails; [`ReadParametersError::Duplicate`] for a parameter that appears
/// twice; [`ReadParametersError::NotAdmitted`] for a parameter that the space
/// does not admit; and [`ReadParametersError::InvalidValue`] for a value
/// that is not a value of the type that claims its ID.
///
/// # Panics
///
/// If the receiver returns a chunk longer than requested, which breaks the
/// `ReadChunk` contract of `nitori_io`; see [`payload`](crate::payload).
#[call(sync)]
pub async fn read_parameters<S, L, F, A>(
    io: &mut A,
    context: S::Context,
    list: PhantomData<(S, L)>,
) -> Result<Parameters<S, L, F::Chunk>, ReadParametersError<F::Error, S::AdmitError, L::ValueErrors>>
where
    S: ParameterSpace,
    L: ParameterList<S>,
    F: ReadChunk<Chunk: Default + Unpin>,
    A: ReceiverAccess<Family = F>,
{
    use read_parameters_error::*;
    // Evaluated when the operation is generated for a concrete list, so a
    // list that breaks the rule does not build.
    const {
        assert!(
            L::DISTINCT_AND_UNRESERVED,
            "two parameter types of the list claim the same ID, or one claims a reserved ID"
        );
    }
    let PhantomData = list;
    let mut parameters = Parameters::<S, L, F::Chunk>::new();
    loop {
        let id = match io.read_var_int().await {
            Ok(id) => id,
            // The source ended between parameters.
            Err(error) if error.is_incomplete() && error.completed() == 0 => break,
            Err(error) => return Err(IdSnafu.into_error(error)),
        };
        let length = io.read_var_int().await.context(LengthSnafu { id })?;
        let length = usize::try_from(length.get()).unwrap_or(usize::MAX);
        let value = read_payload(io, length).await.context(ValueSnafu { id })?;
        // A value that comes back has an ID that no type of the list claims.
        if let Some(value) = L::read_into(&mut parameters.known, id, value, context)? {
            if parameters
                .unknown
                .iter()
                .any(|parameter| parameter.id == id)
            {
                return Err(DuplicateError { id }.into());
            }
            parameters.unknown.push(UnknownParameter { id, value });
        }
    }
    Ok(parameters)
}

/// Failures that [`read_parameters`] can produce.
///
/// `E` is the failure of the source, `A` the reason the space gives for a
/// parameter it does not admit, and `C` the sum of the failures of reading
/// the value of each parameter type of the list
/// ([`ParameterList::ValueErrors`]). Every failure corresponds to the error
/// of the space ([`ParameterSpace::ERROR_CODE`]).
#[derive(Debug, Snafu)]
#[snafu(module(read_parameters_error), visibility(pub(crate)))]
pub enum ReadParametersError<E, A, C> {
    /// The ID of a parameter could not be read.
    #[snafu(display("parameter ID read failed"))]
    Id {
        /// The failure of reading the field.
        source: ReadVarIntError<E>,
    },
    /// The Length of a parameter could not be read.
    #[snafu(display("parameter {:#x} length read failed", id.get()))]
    Length {
        /// The parameter ID.
        id: VarInt,
        /// The failure of reading the field.
        source: ReadVarIntError<E>,
    },
    /// The value of a parameter could not be read from the source.
    #[snafu(display("parameter {:#x} value read failed", id.get()))]
    Value {
        /// The parameter ID.
        id: VarInt,
        /// The failure of reading the value.
        source: ReadPayloadError<E>,
    },
    /// A parameter appears more than once.
    #[snafu(transparent)]
    Duplicate {
        /// The repeated parameter.
        source: DuplicateError,
    },
    /// The space does not admit a parameter.
    #[snafu(transparent)]
    NotAdmitted {
        /// The parameter and the reason.
        source: NotAdmittedError<A>,
    },
    /// The value of a parameter is not a value of the type that claims its
    /// ID.
    #[snafu(display("parameter {:#x} has an invalid value", id.get()))]
    InvalidValue {
        /// The parameter ID.
        id: VarInt,
        /// The failure, of the type that claims the ID.
        source: PartsError<C>,
    },
}

impl<E, A, C> ReadParametersError<E, A, C> {
    /// The ID of the parameter that failed, if it could be read.
    pub fn id(&self) -> Option<VarInt> {
        match self {
            Self::Id { .. } => None,
            Self::Length { id, .. } | Self::Value { id, .. } | Self::InvalidValue { id, .. } => {
                Some(*id)
            }
            Self::Duplicate { source } => Some(source.id()),
            Self::NotAdmitted { source } => Some(source.id()),
        }
    }

    /// Whether the source ended within a parameter.
    ///
    /// A value that is too short for its type is not incomplete: the source
    /// held all of it.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::Id { source } | Self::Length { source, .. } => source.is_incomplete(),
            Self::Value { source, .. } => source.is_incomplete(),
            Self::Duplicate { .. } | Self::NotAdmitted { .. } | Self::InvalidValue { .. } => false,
        }
    }

    /// The failure of reading the value of the parameter type `P`, if this
    /// is one: [`InvalidValue`](Self::InvalidValue) for the ID of `P` with
    /// the failure of `P`.
    ///
    /// Several types of a list can fail with the same type, so the sum `C`
    /// cannot always be taken apart by type alone; this goes by the ID.
    pub fn value_error<P>(&self) -> Option<&P::ValueError>
    where
        P: KeyedParameter,
        C: ErrorCoproduct,
    {
        match self {
            Self::InvalidValue { id, source } if *id == P::ID => {
                source.0.as_error().downcast_ref::<P::ValueError>()
            }
            _ => None,
        }
    }

    /// This failure, of the rest of a list, as a failure of the list with
    /// the type `H` before the rest.
    pub(super) fn after<H>(self) -> ReadParametersError<E, A, Coproduct<H, C>> {
        match self {
            Self::Id { source } => ReadParametersError::Id { source },
            Self::Length { id, source } => ReadParametersError::Length { id, source },
            Self::Value { id, source } => ReadParametersError::Value { id, source },
            Self::Duplicate { source } => ReadParametersError::Duplicate { source },
            Self::NotAdmitted { source } => ReadParametersError::NotAdmitted { source },
            Self::InvalidValue { id, source } => ReadParametersError::InvalidValue {
                id,
                source: PartsError(Coproduct::Inr(source.0)),
            },
        }
    }
}

/// Writes `parameters` as a set of parameters with `context`, after checking
/// them with [`Parameters::validate`].
///
/// The slots that hold a parameter are written in the order of the list,
/// including a parameter that has the default value of its type; empty slots
/// are not written. The unknown parameters follow in their order.
/// Acceptance by the receiver does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteParametersError::Invalid`] before writing anything, and
/// [`WriteParametersError::Write`] if the receiver stops accepting bytes or
/// fails; bytes accepted before stay written, and the error counts them
/// over the whole encoding.
#[call(sync)]
pub async fn write_parameters<S, L, D, F, A>(
    io: &mut A,
    parameters: Parameters<S, L, D>,
    context: S::Context,
) -> Result<(), WriteParametersError<F::Error, S::AdmitError>>
where
    S: ParameterSpace,
    L: ParameterList<S>,
    D: Buf,
    F: Write,
    A: ReceiverAccess<Family = F>,
{
    use write_parameters_error::*;
    // Evaluated when the operation is generated for a concrete list, so a
    // list that breaks the rule does not build.
    const {
        assert!(
            L::DISTINCT_AND_UNRESERVED,
            "two parameter types of the list claim the same ID, or one claims a reserved ID"
        );
    }
    parameters.validate(context)?;
    let mut written = 0;
    L::write(&parameters.known, io, &mut written)
        .await
        .context(WriteSnafu)?;
    for parameter in parameters.unknown {
        let head = item_head(parameter.id, parameter.value.remaining());
        put(io, head.as_slice().chain(parameter.value), &mut written)
            .await
            .context(WriteSnafu)?;
    }
    Ok(())
}

/// Failures that [`write_parameters`] can produce; `A` is the reason the
/// space gives for a parameter it does not admit.
#[derive(Debug, Snafu)]
#[snafu(module(write_parameters_error), visibility(pub(crate)))]
pub enum WriteParametersError<E, A> {
    /// The parameters must not be written; nothing was written.
    #[snafu(transparent)]
    Invalid {
        /// Why they must not be written.
        source: InvalidParametersError<A>,
    },
    /// The receiver stopped accepting bytes or failed.
    #[snafu(display("parameters write failed"))]
    Write {
        /// The failure of writing; it counts the bytes accepted before over
        /// the whole encoding.
        source: WriteAllError<E>,
    },
}
