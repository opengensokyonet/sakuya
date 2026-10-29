//! QUIC versions ([RFC 8999 §5.1]).
//!
//! A [`Version`] is the 32-bit Version field of a long header. Every value is
//! a version; [`Version::V1`] is QUIC version 1 ([RFC 9000]), and
//! [`Version::NEGOTIATION`], the value zero, marks a Version Negotiation
//! packet. Versions of the form `0x?a?a?a?a` are reserved so that endpoints
//! exercise version negotiation ([RFC 9000 §15]).
//!
//! [RFC 8999 §5.1]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
//! [RFC 9000 §15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-15
use core::fmt;

/// A QUIC version: the Version field of a long header.
///
/// Equality, ordering and hashing are those of the numeric value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(u32);

impl Version {
    /// The Version field of a Version Negotiation packet, zero
    /// ([RFC 8999 §6]).
    ///
    /// [RFC 8999 §6]: https://www.rfc-editor.org/rfc/rfc8999.html#section-6
    pub const NEGOTIATION: Self = Self(0);

    /// QUIC version 1, `0x00000001` ([RFC 9000 §15]).
    ///
    /// [RFC 9000 §15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-15
    pub const V1: Self = Self(0x0000_0001);

    /// The bits that are `0xa` in every nibble pair of a reserved version.
    const RESERVED_MASK: u32 = 0x0f0f_0f0f;
    const RESERVED_PATTERN: u32 = 0x0a0a_0a0a;

    /// The version with the numeric value `value`.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The numeric value.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Whether the version follows the reserved pattern `0x?a?a?a?a`, which
    /// endpoints send to exercise version negotiation and which no real
    /// version uses ([RFC 9000 §15]).
    ///
    /// [RFC 9000 §15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-15
    pub const fn is_reserved(self) -> bool {
        self.0 & Self::RESERVED_MASK == Self::RESERVED_PATTERN
    }

    /// The four bytes of the Version field, in network byte order.
    pub const fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl From<u32> for Version {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Version> for u32 {
    fn from(version: Version) -> Self {
        version.0
    }
}

/// Formats the value as eight hexadecimal digits, as in `0x00000001`.
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::Version;

    #[test]
    fn reserved_versions_follow_the_pattern() {
        for value in [0x0a0a_0a0a, 0x1a2a_3a4a, 0xfafa_fafa] {
            assert!(Version::new(value).is_reserved(), "{value:#x}");
        }
        for value in [0, 1, 0x6b33_43cf, 0x0a0a_0a0b, 0xff00_001d] {
            assert!(!Version::new(value).is_reserved(), "{value:#x}");
        }
        assert!(!Version::V1.is_reserved());
        assert!(!Version::NEGOTIATION.is_reserved());
    }

    #[test]
    fn converts_and_formats() {
        assert_eq!(Version::V1.get(), 1);
        assert_eq!(
            Version::from(0x6b33_43cf).to_be_bytes(),
            [0x6b, 0x33, 0x43, 0xcf]
        );
        assert_eq!(u32::from(Version::NEGOTIATION), 0);
        assert_eq!(Version::new(0x6b33_43cf).to_string(), "0x6b3343cf");
        assert_eq!(Version::default(), Version::NEGOTIATION);
    }
}
