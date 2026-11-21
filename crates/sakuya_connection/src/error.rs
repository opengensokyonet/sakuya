//! The error of a connection, from the errors of its parts.
//!
//! Each part of a composition gives the error it finds in a connection
//! ([`ConnectionErrorPart`]), which may depend on the whole list of parts;
//! the connection's error is the sum of those errors in the order of the
//! list of parts, wrapped in a [`PartsError`] ([`ConnectionErrorOf`]). A
//! part puts its own error in by type, without knowing its position.
//!
//! A failure of reading the peer's transport parameters is split the same
//! way: version 1 reads them, and a failure of the encoding as a whole is
//! its error; a value that breaks a rule of its parameter type is the
//! error of the part that defines the type
//! ([`TransportParameterValueErrorPart`]). The failures of the values are
//! a sum over the joined list of the parameter types of all the parts,
//! which [`TransportParameterValueErrorsOf`] takes apart by the length of
//! each part's list.
use core::ops::Add;

use sakuya_wire::parts::{CNil, Coproduct, HCons, HNil, PartsError};
use sakuya_wire_v1::transport_parameters::{
    TransportParameterList, TransportParameterSpace, TransportParameterValueErrors,
};
use sakuya_wire_v1::{
    parameters::{KeyedParameter, ParameterList, ParametersOf, ParametersPart},
    var_int::VarInt,
};

use sakuya_stream_v1::resets::StreamResetsOf;

/// The error a part finds in a connection: the failures of its own frames,
/// components and calls.
///
/// It is implemented by the marker type of each part; `L` is the whole
/// list of parts of the composition, which the error may depend on, as
/// version 1's failure of a RESET_STREAM frame depends on how the
/// composition resets streams.
pub trait ConnectionErrorPart<L> {
    /// The error.
    type ConnectionError;
}

/// The errors of a list of parts in the composition of the whole list
/// `Full`: the sum of the errors of the parts
/// ([`ConnectionErrorPart::ConnectionError`] for `Full`) in the order of
/// the parts.
///
/// It is implemented for `HNil` and for `HCons<P, Ps>` of a part `P` and a
/// list of parts `Ps`.
pub trait ConnectionErrorsIn<Full> {
    /// The sum: a `Coproduct` that ends in `CNil`.
    type ConnectionErrors;
}

impl<Full> ConnectionErrorsIn<Full> for HNil {
    type ConnectionErrors = CNil;
}

impl<Full, P, Ps> ConnectionErrorsIn<Full> for HCons<P, Ps>
where
    P: ConnectionErrorPart<Full>,
    Ps: ConnectionErrorsIn<Full>,
{
    type ConnectionErrors = Coproduct<P::ConnectionError, Ps::ConnectionErrors>;
}

/// The errors of a composition's list of parts: the sum of the errors of
/// its parts ([`ConnectionErrorsIn`] of the list itself).
///
/// The errors depend on how the list resets streams, which it also has
/// ([`StreamResetsOf`]).
pub trait ConnectionErrorsOf: StreamResetsOf {
    /// The sum: a `Coproduct` that ends in `CNil`.
    type ConnectionErrors;
}

impl<L: ConnectionErrorsIn<L> + StreamResetsOf> ConnectionErrorsOf for L {
    type ConnectionErrors = <L as ConnectionErrorsIn<L>>::ConnectionErrors;
}

/// The error of a connection of the list of parts `L`.
pub type ConnectionErrorOf<L> = PartsError<<L as ConnectionErrorsOf>::ConnectionErrors>;

/// How a part's error holds a failure of the value of one of its own
/// transport parameters: `C` is the sum of the failures of reading the
/// values of the part's transport parameter types, in the order of its
/// list, and `L` the whole list of parts.
///
/// It is implemented by the marker type of each part that defines
/// transport parameters; every part has it for `CNil`, the sum of a part
/// without them. Only a value that breaks a rule of its type goes to the
/// part that defines the type; a failure of the encoding as a whole, such
/// as a parameter that appears twice, is an error of version 1, which
/// reads the transport parameters.
pub trait TransportParameterValueErrorPart<C, L>: ConnectionErrorPart<L> {
    /// The error that the value of the parameter `id` breaking a rule of
    /// its type (`source`) is.
    fn value_error(id: VarInt, source: PartsError<C>) -> Self::ConnectionError;
}

impl<L, P: ConnectionErrorPart<L>> TransportParameterValueErrorPart<CNil, L> for P {
    fn value_error(_: VarInt, source: PartsError<CNil>) -> P::ConnectionError {
        match source.0 {}
    }
}

/// The errors of a list of parts in the composition of the whole list
/// `Full` for a failure of the value of a transport parameter, each given
/// by the part whose type claims the parameter
/// ([`TransportParameterValueErrorPart`]).
///
/// It is implemented for `HNil` and for `HCons<P, Ps>` of a part `P` and a
/// list of parts `Ps`.
pub trait TransportParameterValueErrorsIn<Full>:
    ConnectionErrorsIn<Full> + ParametersOf<TransportParameterSpace>
{
    /// The error that the value of the parameter `id` breaking a rule of
    /// its type is: `source` is a failure of the joined list of the
    /// transport parameter types of the parts, and the part whose types
    /// hold its position gives the error, at the part's position.
    fn value_error(
        id: VarInt,
        source: TransportParameterValueErrors<Self>,
    ) -> <Self as ConnectionErrorsIn<Full>>::ConnectionErrors;
}

impl<Full> TransportParameterValueErrorsIn<Full> for HNil {
    fn value_error(_: VarInt, source: CNil) -> CNil {
        match source {}
    }
}

impl<Full, P, Ps> TransportParameterValueErrorsIn<Full> for HCons<P, Ps>
where
    P: ParametersPart<TransportParameterSpace>
        + TransportParameterValueErrorPart<ValueErrorsOfPart<P>, Full>,
    Ps: TransportParameterValueErrorsIn<Full>,
    P::Parameters: Add<TransportParameterList<Ps>>
        + ValueErrorsBefore<
            TransportParameterValueErrors<Ps>,
            Joined = TransportParameterValueErrors<Self>,
        >,
    <P::Parameters as Add<TransportParameterList<Ps>>>::Output:
        ParameterList<TransportParameterSpace>,
{
    fn value_error(
        id: VarInt,
        source: TransportParameterValueErrors<Self>,
    ) -> <Self as ConnectionErrorsIn<Full>>::ConnectionErrors {
        match P::Parameters::split(source) {
            Ok(own) => Coproduct::Inl(P::value_error(id, PartsError(own))),
            Err(rest) => Coproduct::Inr(Ps::value_error(id, rest)),
        }
    }
}

/// The errors of a composition's list of parts for a failure of the value
/// of a transport parameter ([`TransportParameterValueErrorsIn`] of the
/// list itself).
pub trait TransportParameterValueErrorsOf:
    ConnectionErrorsOf + ParametersOf<TransportParameterSpace>
{
    /// The error that the value of the parameter `id` breaking a rule of
    /// its type is, as [`TransportParameterValueErrorsIn::value_error`].
    fn value_error(
        id: VarInt,
        source: TransportParameterValueErrors<Self>,
    ) -> Self::ConnectionErrors;
}

impl<L> TransportParameterValueErrorsOf for L
where
    L: TransportParameterValueErrorsIn<L> + StreamResetsOf,
{
    fn value_error(
        id: VarInt,
        source: TransportParameterValueErrors<Self>,
    ) -> <L as ConnectionErrorsIn<L>>::ConnectionErrors {
        <L as TransportParameterValueErrorsIn<L>>::value_error(id, source)
    }
}

/// The sum of the failures of reading the values of the transport
/// parameter types of the part `P`.
type ValueErrorsOfPart<P> =
    <<P as ParametersPart<TransportParameterSpace>>::Parameters as ParameterList<
        TransportParameterSpace,
    >>::ValueErrors;

/// A list of transport parameter types whose failures come first in a sum
/// `Joined`, before the failures `Rest` of the types after it, as when the
/// lists of the parts are joined.
pub(crate) trait ValueErrorsBefore<Rest>: ParameterList<TransportParameterSpace> {
    /// The failures of this list, then `Rest`.
    type Joined;

    /// The failure of this list that `joined` is, or the failure of the
    /// types after it.
    fn split(joined: Self::Joined) -> Result<Self::ValueErrors, Rest>;
}

impl<Rest> ValueErrorsBefore<Rest> for HNil {
    type Joined = Rest;

    fn split(joined: Rest) -> Result<CNil, Rest> {
        Err(joined)
    }
}

impl<H, T, Rest> ValueErrorsBefore<Rest> for HCons<H, T>
where
    H: KeyedParameter<Space = TransportParameterSpace>,
    T: ValueErrorsBefore<Rest>,
{
    type Joined = Coproduct<H::ValueError, T::Joined>;

    fn split(joined: Self::Joined) -> Result<Self::ValueErrors, Rest> {
        match joined {
            Coproduct::Inl(error) => Ok(Coproduct::Inl(error)),
            Coproduct::Inr(rest) => T::split(rest).map(Coproduct::Inr),
        }
    }
}
