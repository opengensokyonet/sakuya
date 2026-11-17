//! Reading and writing a set of parameters.
//!
//! [`read_parameters`] reads a sequence of parameters to the end of its
//! source into the slots of a list of parameter types, and
//! [`write_parameters`] writes it; the
//! [module documentation](super#reading-and-writing) describes both.
//!
//! A space has functions of its own that name it, such as
//! [`read_transport_parameters`](crate::v1::transport_parameters::codec::read_transport_parameters),
//! which run these.
use super::{
    DuplicateError, InvalidParametersError, KeyedParameter, NotAdmittedError, ParameterList,
    ParameterSpace, Parameters, UnknownParameter, item_head,
};
use crate::{
    parts::{Coproduct, ErrorCoproduct, PartsError},
    source::read_payload,
    var_int::{VarInt, codec::read_var_int},
};
use bytes::{Buf, BufMut};
use core::marker::PhantomData;
use nitori_io::{SplitTo, error::IncompleteError};
use snafu::{IntoError, ResultExt, Snafu};

/// Reads the parameters of the list `L` in the space `S`, which `list`
/// names, from a set of parameters with `context`: the whole source.
///
/// Values of unknown parameters are pieces of the source.
///
/// # Errors
///
/// [`ReadParametersError::Id`], [`ReadParametersError::Length`] or
/// [`ReadParametersError::Value`] if the source ends within a parameter; [`ReadParametersError::Duplicate`] for a parameter that appears
/// twice; [`ReadParametersError::NotAdmitted`] for a parameter that the space
/// does not admit; and [`ReadParametersError::InvalidValue`] for a value
/// that is not a value of the type that claims its ID.
// The type spells out the failures of the space and of the list.
#[allow(clippy::type_complexity)]
pub fn read_parameters<S, L, B>(
    src: &mut B,
    context: S::Context,
    list: PhantomData<(S, L)>,
) -> Result<Parameters<S, L, B>, ReadParametersError<S::AdmitError, L::ValueErrors>>
where
    S: ParameterSpace,
    L: ParameterList<S>,
    B: Buf + SplitTo,
{
    use read_parameters_error::*;
    // Evaluated when the function is generated for a concrete list, so a
    // list that breaks the rule does not build.
    const {
        assert!(
            L::DISTINCT_AND_UNRESERVED,
            "two parameter types of the list claim the same ID, or one claims a reserved ID"
        );
    }
    let PhantomData = list;
    let mut parameters = Parameters::<S, L, B>::new();
    loop {
        let id = match read_var_int(src) {
            Ok(id) => id,
            // The source ended between parameters.
            Err(error) if error.completed() == 0 => break,
            Err(error) => return Err(IdSnafu.into_error(error)),
        };
        let length = read_var_int(src).context(LengthSnafu { id })?;
        let length = usize::try_from(length.get()).unwrap_or(usize::MAX);
        let value = read_payload(src, length).context(ValueSnafu { id })?;
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
/// `A` is the reason the space gives for a parameter it does not admit, and `C` the sum of the failures of reading
/// the value of each parameter type of the list
/// ([`ParameterList::ValueErrors`]). Every failure corresponds to the error
/// of the space ([`ParameterSpace::ERROR_CODE`]).
#[derive(Debug, Snafu)]
#[snafu(module(read_parameters_error), visibility(pub(crate)))]
pub enum ReadParametersError<A, C> {
    /// The ID of a parameter could not be read.
    #[snafu(display("parameter ID read failed"))]
    Id {
        /// The failure of reading the field.
        source: IncompleteError,
    },
    /// The Length of a parameter could not be read.
    #[snafu(display("parameter {:#x} length read failed", id.get()))]
    Length {
        /// The parameter ID.
        id: VarInt,
        /// The failure of reading the field.
        source: IncompleteError,
    },
    /// The value of a parameter could not be read from the source.
    #[snafu(display("parameter {:#x} value read failed", id.get()))]
    Value {
        /// The parameter ID.
        id: VarInt,
        /// The failure of reading the value.
        source: IncompleteError,
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

impl<A, C> ReadParametersError<A, C> {
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
            Self::Id { .. } | Self::Length { .. } | Self::Value { .. } => true,
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
    pub(super) fn after<H>(self) -> ReadParametersError<A, Coproduct<H, C>> {
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
///
/// # Errors
///
/// [`InvalidParametersError`] if the parameters must not be written; the
/// check comes first, so nothing is written then.
///
/// # Panics
///
/// If `dst` has no room for the parameters, as [`BufMut`] does.
pub fn write_parameters<S, L, D>(
    dst: &mut impl BufMut,
    parameters: Parameters<S, L, D>,
    context: S::Context,
) -> Result<(), InvalidParametersError<S::AdmitError>>
where
    S: ParameterSpace,
    L: ParameterList<S>,
    D: Buf,
{
    // Evaluated when the function is generated for a concrete list, so a
    // list that breaks the rule does not build.
    const {
        assert!(
            L::DISTINCT_AND_UNRESERVED,
            "two parameter types of the list claim the same ID, or one claims a reserved ID"
        );
    }
    parameters.validate(context)?;
    L::write(&parameters.known, dst);
    for parameter in parameters.unknown {
        let head = item_head(parameter.id, parameter.value.remaining());
        dst.put_slice(head.as_slice());
        dst.put(parameter.value);
    }
    Ok(())
}
