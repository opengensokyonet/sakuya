//! Connection IDs as the version-independent long header carries them
//! ([RFC 8999 §5.1]).
//!
//! A [`RawConnectionId`] is a connection ID of 0 to
//! [`RawConnectionId::MAX_LEN`] bytes. It compares, orders and hashes as its
//! bytes; its storage is not part of the interface. The connection IDs of
//! QUIC version 1 are limited to 20 bytes and defined by the package
//! `sakuya_wire_v1` (`sakuya_wire_v1::connection_id::ConnectionId`), which
//! converts from and into a [`RawConnectionId`].
//!
//! The [`codec`] module reads the length-prefixed form of connection IDs
//! that long headers use.
//!
//! [RFC 8999 §5.1]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
use core::{
    borrow::Borrow,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
use snafu::Snafu;

pub mod codec;

/// A connection ID as the version-independent long header carries it: 0 to
/// 255 bytes ([RFC 8999 §5.1]).
///
/// Equality, ordering and hashing are those of [`RawConnectionId::as_bytes`].
/// The package `sakuya_wire_v1` converts it into a connection ID of QUIC
/// version 1, which applies the limit of 20 bytes.
///
/// [RFC 8999 §5.1]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
#[derive(Clone, Copy)]
pub struct RawConnectionId {
    pub(crate) len: u8,
    pub(crate) bytes: [u8; Self::MAX_LEN],
}

impl RawConnectionId {
    /// The longest connection ID a long header can carry, in bytes.
    pub const MAX_LEN: usize = 255;

    /// The zero-length connection ID.
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; Self::MAX_LEN],
    };

    /// Copies a connection ID from `bytes`.
    ///
    /// This is the `const` form of `RawConnectionId::try_from(bytes)`.
    ///
    /// # Errors
    ///
    /// [`RawConnectionIdLengthError`] if `bytes` is longer than
    /// [`RawConnectionId::MAX_LEN`].
    pub const fn new(bytes: &[u8]) -> Result<Self, RawConnectionIdLengthError> {
        if bytes.len() > Self::MAX_LEN {
            return Err(RawConnectionIdLengthError {
                length: bytes.len(),
            });
        }
        let mut id = Self::EMPTY;
        let (prefix, _) = id.bytes.split_at_mut(bytes.len());
        prefix.copy_from_slice(bytes);
        id.len = bytes.len() as u8;
        Ok(id)
    }

    /// The bytes of the connection ID.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The length in bytes.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether this is the zero-length connection ID.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for RawConnectionId {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl TryFrom<&[u8]> for RawConnectionId {
    type Error = RawConnectionIdLengthError;

    /// Copies a connection ID from the slice; see [`RawConnectionId::new`].
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for RawConnectionId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<[u8]> for RawConnectionId {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq for RawConnectionId {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for RawConnectionId {}

impl PartialOrd for RawConnectionId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RawConnectionId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Hash for RawConnectionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

/// Formats the bytes as lowercase hexadecimal, as in `RawConnectionId(8394c8f0)`.
impl fmt::Debug for RawConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawConnectionId({})", Hex(self.as_bytes()))
    }
}

/// Formats the bytes as lowercase hexadecimal; the empty ID formats as nothing.
impl fmt::Display for RawConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(self.as_bytes()), f)
    }
}

/// A byte slice exceeds [`RawConnectionId::MAX_LEN`].
///
/// Only [`RawConnectionId::new`] and the conversions into
/// [`RawConnectionId`] construct it, so the length it holds always exceeds
/// 255.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("connection ID of {length} bytes exceeds the long header maximum of 255 bytes"))]
pub struct RawConnectionIdLengthError {
    length: usize,
}

impl RawConnectionIdLengthError {
    /// The rejected length, above 255.
    pub const fn length(self) -> usize {
        self.length
    }
}

/// Lowercase hexadecimal formatting of a byte slice.
struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[cfg(test)]
mod tests;
