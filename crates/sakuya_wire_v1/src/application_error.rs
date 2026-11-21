//! Application protocol error codes ([RFC 9000 §20.2]).
//!
//! An [`ApplicationErrorCode`] is the error code of RESET_STREAM,
//! STOP_SENDING, RESET_STREAM_AT and the application form of
//! CONNECTION_CLOSE (type `0x1d`). Its meaning belongs to the application
//! protocol; QUIC does not interpret it.
//!
//! [RFC 9000 §20.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-20.2
use crate::var_int::VarInt;
use core::fmt;

/// An application protocol error code.
///
/// Every [`VarInt`] is an application error code. Equality, ordering and
/// hashing are those of the numeric value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationErrorCode(VarInt);

impl ApplicationErrorCode {
    /// The application error code with the value `value`.
    pub const fn new(value: VarInt) -> Self {
        Self(value)
    }

    /// The code as a variable-length integer.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<VarInt> for ApplicationErrorCode {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<ApplicationErrorCode> for VarInt {
    fn from(code: ApplicationErrorCode) -> Self {
        code.0
    }
}

/// Formats the value in hexadecimal, as in `0x10c`.
impl fmt::Display for ApplicationErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0.get())
    }
}
