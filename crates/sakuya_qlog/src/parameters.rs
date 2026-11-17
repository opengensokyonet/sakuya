//! How transport parameters are written into `parameters_set`
//! (quic-events §5.3): each parameter type writes itself
//! ([`QlogParameter`]), and the slots of a list of parts write each
//! parameter they hold ([`QlogParameterSlots`]).

use sakuya_wire::{
    parameters::KeyedParameter,
    parts::{HCons, HNil},
};

use crate::json::ObjectWriter;

/// How a transport parameter is written: as one or more members of the data
/// of `parameters_set`.
pub trait QlogParameter: KeyedParameter {
    /// Writes the parameter's members into `parameters`.
    fn write(&self, parameters: &mut ObjectWriter<'_>);
}

/// The slots of the transport parameters of a list of parts, which write
/// each parameter they hold.
pub trait QlogParameterSlots {
    /// Writes the members of every parameter held into `parameters`, in the
    /// order of the slots.
    fn write_parameters(&self, parameters: &mut ObjectWriter<'_>);
}

impl QlogParameterSlots for HNil {
    fn write_parameters(&self, _: &mut ObjectWriter<'_>) {}
}

impl<H: QlogParameter, T: QlogParameterSlots> QlogParameterSlots for HCons<Option<H>, T> {
    fn write_parameters(&self, parameters: &mut ObjectWriter<'_>) {
        if let Some(parameter) = &self.head {
            parameter.write(parameters);
        }
        self.tail.write_parameters(parameters);
    }
}
