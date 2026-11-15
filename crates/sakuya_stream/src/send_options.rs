//! The options a write carries: the send parameters and the destination
//! ([`SendOptions`]), or none yet ([`NoSendOptions`]).
//!
//! A write copies its options onto the data it hands over, so that a later
//! change of options leaves that data as it was written. The send buffer
//! orders a stream's data by the parameters ([`urgency`]) and groups it by
//! the destination ([`destination`]), which decides itself where to fall
//! back when sending there fails.
pub mod destination;
pub mod urgency;

/// The send parameters `P` and the destination `D` that a write carries
/// (`SendOptions`).
///
/// Writing copies the pair onto the data, so it is `Clone`; `PartialEq` lets
/// the send buffer tell whether the next data's parameters or destination
/// changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SendOptions<P, D> {
    parameters: P,
    destination: D,
}

impl<P, D> SendOptions<P, D> {
    /// The options with `parameters` and `destination`.
    pub const fn new(parameters: P, destination: D) -> Self {
        Self {
            parameters,
            destination,
        }
    }

    /// The send parameters.
    pub const fn parameters(&self) -> &P {
        &self.parameters
    }

    /// The send parameters, to change.
    pub const fn parameters_mut(&mut self) -> &mut P {
        &mut self.parameters
    }

    /// The destination.
    pub const fn destination(&self) -> &D {
        &self.destination
    }

    /// The destination, to change; a send buffer changes it when it lets
    /// the destination fall back.
    pub const fn destination_mut(&mut self) -> &mut D {
        &mut self.destination
    }

    /// The send parameters and the destination.
    pub fn into_parts(self) -> (P, D) {
        (self.parameters, self.destination)
    }
}

/// No send parameters and no destination set yet (`NoSendOptions`): the
/// state of a stream writer before the application chooses where and in
/// what order its data goes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NoSendOptions;

#[cfg(test)]
mod tests;
