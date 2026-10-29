//! Transport error codes ([RFC 9000 §20.1]).
//!
//! A [`TransportErrorCode`] is the Error Code field of a CONNECTION_CLOSE
//! frame of type `0x1c`. The decoders in this crate name the code their
//! failures correspond to, so that the connection can close with it.
//!
//! [RFC 9000 §20.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-20.1
use crate::var_int::VarInt;
use core::fmt;

/// A QUIC transport error code.
///
/// Every [`VarInt`] is a transport error code; the associated constants are
/// those RFC 9000 defines. Equality, ordering and hashing are those of the
/// numeric value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportErrorCode(VarInt);

impl TransportErrorCode {
    /// `0x00`: the connection closes without an error.
    pub const NO_ERROR: Self = Self::from_u32(0x00);
    /// `0x01`: the endpoint encountered an internal error.
    pub const INTERNAL_ERROR: Self = Self::from_u32(0x01);
    /// `0x02`: the server refuses to accept a new connection.
    pub const CONNECTION_REFUSED: Self = Self::from_u32(0x02);
    /// `0x03`: more data was received than the advertised limits permit.
    pub const FLOW_CONTROL_ERROR: Self = Self::from_u32(0x03);
    /// `0x04`: a stream was opened beyond the advertised stream limit.
    pub const STREAM_LIMIT_ERROR: Self = Self::from_u32(0x04);
    /// `0x05`: a frame arrived for a stream in a state that does not permit it.
    pub const STREAM_STATE_ERROR: Self = Self::from_u32(0x05);
    /// `0x06`: a final size was violated.
    pub const FINAL_SIZE_ERROR: Self = Self::from_u32(0x06);
    /// `0x07`: a frame was badly formatted.
    pub const FRAME_ENCODING_ERROR: Self = Self::from_u32(0x07);
    /// `0x08`: transport parameters were malformed, invalid or missing.
    pub const TRANSPORT_PARAMETER_ERROR: Self = Self::from_u32(0x08);
    /// `0x09`: more connection IDs were provided than the advertised limit.
    pub const CONNECTION_ID_LIMIT_ERROR: Self = Self::from_u32(0x09);
    /// `0x0a`: a protocol violation not covered by a more specific code.
    pub const PROTOCOL_VIOLATION: Self = Self::from_u32(0x0a);
    /// `0x0b`: a Retry or NEW_TOKEN token was invalid.
    pub const INVALID_TOKEN: Self = Self::from_u32(0x0b);
    /// `0x0c`: the application or application protocol caused the close.
    pub const APPLICATION_ERROR: Self = Self::from_u32(0x0c);
    /// `0x0d`: more data was received in CRYPTO frames than can be buffered.
    pub const CRYPTO_BUFFER_EXCEEDED: Self = Self::from_u32(0x0d);
    /// `0x0e`: a key update was performed incorrectly.
    pub const KEY_UPDATE_ERROR: Self = Self::from_u32(0x0e);
    /// `0x0f`: the confidentiality or integrity limit of the AEAD was reached.
    pub const AEAD_LIMIT_REACHED: Self = Self::from_u32(0x0f);
    /// `0x10`: no network path is able to support QUIC.
    pub const NO_VIABLE_PATH: Self = Self::from_u32(0x10);

    const CRYPTO_ERROR_BASE: u32 = 0x0100;

    const fn from_u32(value: u32) -> Self {
        Self(VarInt::from_u32(value))
    }

    /// `0x0100` plus `alert`: the cryptographic handshake failed with a TLS
    /// alert.
    pub const fn crypto_error(alert: u8) -> Self {
        Self::from_u32(Self::CRYPTO_ERROR_BASE + alert as u32)
    }

    /// The TLS alert of a code in the CRYPTO_ERROR range `0x0100..=0x01ff`.
    pub const fn crypto_alert(self) -> Option<u8> {
        let value = self.0.get();
        if value >= Self::CRYPTO_ERROR_BASE as u64 && value <= 0x01ff {
            Some((value - Self::CRYPTO_ERROR_BASE as u64) as u8)
        } else {
            None
        }
    }

    /// The code as a variable-length integer.
    pub const fn get(self) -> VarInt {
        self.0
    }

    /// The name RFC 9000 gives the code, if it defines one.
    ///
    /// Codes in the CRYPTO_ERROR range are named `CRYPTO_ERROR`.
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0.get() {
            0x00 => "NO_ERROR",
            0x01 => "INTERNAL_ERROR",
            0x02 => "CONNECTION_REFUSED",
            0x03 => "FLOW_CONTROL_ERROR",
            0x04 => "STREAM_LIMIT_ERROR",
            0x05 => "STREAM_STATE_ERROR",
            0x06 => "FINAL_SIZE_ERROR",
            0x07 => "FRAME_ENCODING_ERROR",
            0x08 => "TRANSPORT_PARAMETER_ERROR",
            0x09 => "CONNECTION_ID_LIMIT_ERROR",
            0x0a => "PROTOCOL_VIOLATION",
            0x0b => "INVALID_TOKEN",
            0x0c => "APPLICATION_ERROR",
            0x0d => "CRYPTO_BUFFER_EXCEEDED",
            0x0e => "KEY_UPDATE_ERROR",
            0x0f => "AEAD_LIMIT_REACHED",
            0x10 => "NO_VIABLE_PATH",
            0x0100..=0x01ff => "CRYPTO_ERROR",
            _ => return None,
        })
    }
}

impl From<VarInt> for TransportErrorCode {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<TransportErrorCode> for VarInt {
    fn from(code: TransportErrorCode) -> Self {
        code.0
    }
}

/// Formats the RFC name and the value, as in `FRAME_ENCODING_ERROR (0x7)`, or
/// the value alone for codes RFC 9000 does not name.
impl fmt::Display for TransportErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({:#x})", self.0.get()),
            None => write!(f, "{:#x}", self.0.get()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TransportErrorCode;

    #[test]
    fn names_and_crypto_range() {
        assert_eq!(
            TransportErrorCode::FRAME_ENCODING_ERROR.to_string(),
            "FRAME_ENCODING_ERROR (0x7)"
        );
        let alert = TransportErrorCode::crypto_error(0x2a);
        assert_eq!(alert.get().get(), 0x012a);
        assert_eq!(alert.crypto_alert(), Some(0x2a));
        assert_eq!(alert.name(), Some("CRYPTO_ERROR"));
        assert_eq!(TransportErrorCode::NO_VIABLE_PATH.crypto_alert(), None);
        assert_eq!(
            TransportErrorCode::from(crate::var_int::VarInt::from(0x11u8)).to_string(),
            "0x11"
        );
    }
}
