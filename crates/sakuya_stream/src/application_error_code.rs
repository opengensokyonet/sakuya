//! Application protocol error codes.
//!
//! An [`ApplicationErrorCode`] is the error code an application protocol
//! chooses for `RESET_STREAM`, `RESET_STREAM_AT` and `STOP_SENDING`
//! ([RFC 9000 §20.2]). Its meaning belongs to the application protocol; the
//! transport only carries it.
//!
//! [RFC 9000 §20.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-20.2
use core::fmt;
use sakuya_wire::var_int::VarInt;

/// An application protocol error code.
///
/// Every [`VarInt`] is an application protocol error code. Equality,
/// ordering and hashing are those of the numeric value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationErrorCode(VarInt);

impl ApplicationErrorCode {
    /// The code with the numeric value `code`.
    pub const fn new(code: VarInt) -> Self {
        Self(code)
    }

    /// The code as a variable-length integer.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<VarInt> for ApplicationErrorCode {
    fn from(code: VarInt) -> Self {
        Self(code)
    }
}

impl From<ApplicationErrorCode> for VarInt {
    fn from(code: ApplicationErrorCode) -> Self {
        code.0
    }
}

/// Formats the numeric value.
impl fmt::Display for ApplicationErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::ApplicationErrorCode;
    use sakuya_wire::var_int::VarInt;

    #[test]
    fn wraps_and_formats_the_value() {
        let value = VarInt::from_u32(0x10c);
        let code = ApplicationErrorCode::new(value);
        assert_eq!(code.get(), value);
        assert_eq!(ApplicationErrorCode::from(value), code);
        assert_eq!(VarInt::from(code), value);
        assert_eq!(code.to_string(), "268");
        assert!(ApplicationErrorCode::default() < code);
    }
}
