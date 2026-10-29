//! Connection IDs ([RFC 9000 §5.1]).
//!
//! A [`ConnectionId`] is a QUIC version 1 connection ID of 0 to
//! [`ConnectionId::MAX_LEN`] bytes. A [`NonEmptyCid`] is a connection ID that
//! is known to have at least one byte. Both compare, order and hash as their
//! bytes; their storage is not part of the interface.
//!
//! Connection IDs of other QUIC versions may be longer; the version-independent
//! header interpretation in [`crate::header`] reports them as byte slices.
//!
//! [RFC 9000 §5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
use core::{
    borrow::Borrow,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
use snafu::Snafu;

/// A QUIC version 1 connection ID: 0 to 20 bytes.
///
/// Equality, ordering and hashing are those of [`ConnectionId::as_bytes`],
/// so a connection ID can be looked up by a byte slice through
/// [`Borrow<[u8]>`](Borrow). The [`Default`] value is [`ConnectionId::EMPTY`].
#[derive(Clone, Copy)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; Self::MAX_LEN],
}

impl ConnectionId {
    /// The longest connection ID QUIC version 1 allows, in bytes
    /// ([RFC 9000 §17.2]).
    ///
    /// [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
    pub const MAX_LEN: usize = 20;

    /// The zero-length connection ID.
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; Self::MAX_LEN],
    };

    /// Copies a connection ID from `bytes`.
    ///
    /// This is the `const` form of `ConnectionId::try_from(bytes)`.
    ///
    /// # Errors
    ///
    /// [`ConnectionIdLengthError`] if `bytes` is longer than
    /// [`ConnectionId::MAX_LEN`].
    pub const fn new(bytes: &[u8]) -> Result<Self, ConnectionIdLengthError> {
        if bytes.len() > Self::MAX_LEN {
            return Err(ConnectionIdLengthError {
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

impl Default for ConnectionId {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl TryFrom<&[u8]> for ConnectionId {
    type Error = ConnectionIdLengthError;

    /// Copies a connection ID from the slice; see [`ConnectionId::new`].
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<[u8]> for ConnectionId {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq for ConnectionId {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for ConnectionId {}

impl PartialOrd for ConnectionId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConnectionId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Hash for ConnectionId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

/// Formats the bytes as lowercase hexadecimal, as in `ConnectionId(8394c8f0)`.
impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionId({})", Hex(self.as_bytes()))
    }
}

/// Formats the bytes as lowercase hexadecimal; the empty ID formats as nothing.
impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(self.as_bytes()), f)
    }
}

/// A byte slice exceeds [`ConnectionId::MAX_LEN`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("connection ID of {length} bytes exceeds the QUIC version 1 maximum of 20 bytes"))]
pub struct ConnectionIdLengthError {
    /// The rejected length.
    pub length: usize,
}

/// A connection ID of 1 to 20 bytes.
///
/// It compares, orders and hashes as the [`ConnectionId`] it wraps, and
/// therefore as its bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonEmptyCid(ConnectionId);

impl NonEmptyCid {
    /// Returns `id` as a non-empty connection ID, or `None` if it is empty.
    pub const fn new(id: ConnectionId) -> Option<Self> {
        if id.is_empty() { None } else { Some(Self(id)) }
    }

    /// The connection ID.
    pub const fn get(self) -> ConnectionId {
        self.0
    }

    /// The bytes of the connection ID: 1 to [`ConnectionId::MAX_LEN`].
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for NonEmptyCid {
    type Error = NonEmptyCidError;

    /// Copies a non-empty connection ID from the slice.
    ///
    /// # Errors
    ///
    /// [`NonEmptyCidError::Empty`] for an empty slice and
    /// [`NonEmptyCidError::Length`] for one longer than
    /// [`ConnectionId::MAX_LEN`].
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let id = ConnectionId::new(bytes)?;
        Self::new(id).ok_or(NonEmptyCidError::Empty)
    }
}

impl TryFrom<ConnectionId> for NonEmptyCid {
    type Error = NonEmptyCidError;

    /// Accepts a non-empty connection ID; see [`NonEmptyCid::new`].
    ///
    /// # Errors
    ///
    /// [`NonEmptyCidError::Empty`] for the zero-length connection ID.
    fn try_from(id: ConnectionId) -> Result<Self, Self::Error> {
        Self::new(id).ok_or(NonEmptyCidError::Empty)
    }
}

impl From<NonEmptyCid> for ConnectionId {
    fn from(id: NonEmptyCid) -> Self {
        id.0
    }
}

impl AsRef<ConnectionId> for NonEmptyCid {
    fn as_ref(&self) -> &ConnectionId {
        &self.0
    }
}

impl AsRef<[u8]> for NonEmptyCid {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Borrow<[u8]> for NonEmptyCid {
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Formats the bytes as lowercase hexadecimal, as in `NonEmptyCid(8394c8f0)`.
impl fmt::Debug for NonEmptyCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NonEmptyCid({})", Hex(self.as_bytes()))
    }
}

/// Formats the bytes as lowercase hexadecimal.
impl fmt::Display for NonEmptyCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&Hex(self.as_bytes()), f)
    }
}

/// Failures of converting to a [`NonEmptyCid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum NonEmptyCidError {
    /// The connection ID has no bytes.
    #[snafu(display("connection ID is empty"))]
    Empty,
    /// The bytes are too long for a connection ID.
    #[snafu(transparent)]
    Length {
        /// The rejected length.
        source: ConnectionIdLengthError,
    },
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
