//! How transport parameters are written into `parameters_set`
//! (quic-events §5.3): each part of qlog's writer writes the parameter
//! types of the part of the connection it stands for
//! ([`QlogParameter`]), and a list of qlog's parts writes the slots of the
//! connection's list, each part the slots of its own types
//! ([`QlogParameterSlots`]).
//!
//! The slots of a list of parts are one flat list, the parameter types of
//! each part in the order of the parts
//! ([`ParametersOf`](sakuya_wire::parameters::ParametersOf)). A part of
//! qlog's writer writes as many slots from the front as its part of the
//! connection has parameter types ([`QlogParameterList`]) and leaves the
//! rest to the next part.

use sakuya_wire::{
    parameters::ParametersPart,
    parts::{HCons, HNil},
    v1::transport_parameters::TransportParameterSpace,
};

use crate::{QlogPart, json::ObjectWriter};

/// How the part of qlog's writer `Self` writes the transport parameter
/// type `H` of the part of the connection it stands for: as one or more
/// members of the data of `parameters_set`.
pub trait QlogParameter<H> {
    /// Writes the members of `parameter` into `data`.
    fn write(parameter: &H, data: &mut ObjectWriter<'_>);
}

/// A list of parameter types, those of one part of a connection, whose
/// slots lead the slots `S`: the part of qlog's writer `Q` writes each of
/// them it holds ([`QlogParameter`]), and the slots after them are
/// [`Rest`](Self::Rest).
///
/// It is implemented for `HNil`, which leads with no slot, and for
/// `HCons<H, Hs>` over slots `HCons<Option<H>, T>` whose tail `T` the
/// list `Hs` leads.
pub trait QlogParameterList<Q, S> {
    /// The slots after those of the list.
    type Rest;

    /// Writes the parameters the leading slots of `slots` hold into
    /// `data`, in the order of the slots, and gives the slots after them.
    fn write_leading<'s>(slots: &'s S, data: &mut ObjectWriter<'_>) -> &'s Self::Rest;
}

impl<Q, S> QlogParameterList<Q, S> for HNil {
    type Rest = S;

    fn write_leading<'s>(slots: &'s S, _: &mut ObjectWriter<'_>) -> &'s S {
        slots
    }
}

impl<Q, H, Hs, T> QlogParameterList<Q, HCons<Option<H>, T>> for HCons<H, Hs>
where
    Q: QlogParameter<H>,
    Hs: QlogParameterList<Q, T>,
{
    type Rest = Hs::Rest;

    fn write_leading<'s>(
        slots: &'s HCons<Option<H>, T>,
        data: &mut ObjectWriter<'_>,
    ) -> &'s Self::Rest {
        if let Some(parameter) = &slots.head {
            Q::write(parameter, data);
        }
        Hs::write_leading(&slots.tail, data)
    }
}

/// A list of qlog's parts that writes the slots `S` of the transport
/// parameters of the list of parts of the connection it stands for: each
/// part writes the slots of its part's parameter types, from the front,
/// and the next part the slots after them.
pub trait QlogParameterSlots<S> {
    /// Writes the members of every parameter `slots` hold into `data`, in
    /// the order of the slots.
    fn write_parameters(slots: &S, data: &mut ObjectWriter<'_>);
}

/// The parameter types of the part of the connection the part of qlog's
/// writer `Q` stands for.
type PartParameters<Q> =
    <<Q as QlogPart>::Connection as ParametersPart<TransportParameterSpace>>::Parameters;

impl QlogParameterSlots<HNil> for HNil {
    fn write_parameters(_: &HNil, _: &mut ObjectWriter<'_>) {}
}

impl<Q, Qs, S> QlogParameterSlots<S> for HCons<Q, Qs>
where
    Q: QlogPart<Connection: ParametersPart<TransportParameterSpace>>,
    PartParameters<Q>: QlogParameterList<Q, S>,
    Qs: QlogParameterSlots<<PartParameters<Q> as QlogParameterList<Q, S>>::Rest>,
{
    fn write_parameters(slots: &S, data: &mut ObjectWriter<'_>) {
        let rest = PartParameters::<Q>::write_leading(slots, data);
        Qs::write_parameters(rest, data);
    }
}
