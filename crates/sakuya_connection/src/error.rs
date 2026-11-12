//! The error of a connection, from the errors of its parts.
//!
//! Each part of a composition gives the error it finds in a connection
//! ([`ConnectionErrorPart`]); the connection's error is the sum of those
//! errors in the order of the list of parts, wrapped in a [`PartsError`]
//! ([`ConnectionErrorOf`]). A part puts its own error in by type, without
//! knowing its position.
use sakuya_wire::parts::{CNil, Coproduct, HCons, HNil, PartsError};

/// The error a part finds in a connection: the failures of its own frames,
/// components and calls.
///
/// It is implemented by the marker type of each part.
pub trait ConnectionErrorPart {
    /// The error.
    type ConnectionError;
}

/// The errors of a list of parts: the sum of the errors of the parts
/// ([`ConnectionErrorPart::ConnectionError`]) in the order of the parts.
///
/// It is implemented for `HNil` and for `HCons<P, Ps>` of a part `P` and a
/// list of parts `Ps`.
pub trait ConnectionErrorsOf {
    /// The sum: a `Coproduct` that ends in `CNil`.
    type ConnectionErrors;
}

impl ConnectionErrorsOf for HNil {
    type ConnectionErrors = CNil;
}

impl<P: ConnectionErrorPart, Ps: ConnectionErrorsOf> ConnectionErrorsOf for HCons<P, Ps> {
    type ConnectionErrors = Coproduct<P::ConnectionError, Ps::ConnectionErrors>;
}

/// The error of a connection of the list of parts `L`.
pub type ConnectionErrorOf<L> = PartsError<<L as ConnectionErrorsOf>::ConnectionErrors>;
