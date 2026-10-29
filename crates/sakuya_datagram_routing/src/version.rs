//! QUIC versions as routing reads them from long headers

use std::fmt;

use sakuya_wire::header::v1;

/// The version field of a QUIC long header.
///
/// Any 32-bit value is a version field; whether this side supports it is a
/// separate question. The value 0 identifies a Version Negotiation packet
/// rather than a version.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(u32);

impl Version {
    /// QUIC version 1 ([RFC 9000]).
    ///
    /// [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
    pub const V1: Self = Self(v1::VERSION);

    /// The version field with this value.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The value of the version field.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Whether the field identifies a Version Negotiation packet.
    pub const fn is_negotiation(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Version({:#010x})", self.0)
    }
}
