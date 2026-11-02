//! Connection IDs ([RFC 9000 §5.1]).
//!
//! A [`ConnectionId`] is a QUIC version 1 connection ID of 0 to
//! [`ConnectionId::MAX_LEN`] bytes, and a [`ConnectionIdLength`] is the
//! length of one. A [`NonEmptyCid`] is a connection ID that
//! is known to have at least one byte. A [`RawConnectionId`] is a connection
//! ID as the version-independent long header carries it, 0 to
//! [`RawConnectionId::MAX_LEN`] bytes ([RFC 8999 §5.1]); converting it into
//! a [`ConnectionId`] applies the version 1 limit. All three compare, order
//! and hash as their bytes; their storage is not part of the interface.
//!
//! A [`StatelessResetToken`] is the 16-byte token that NEW_CONNECTION_ID and
//! the transport parameters associate with a connection ID
//! ([RFC 9000 §10.3]).
//!
//! The [`codec`] module reads and writes the length-prefixed form of
//! connection IDs that long headers and frames use.
//!
//! [RFC 8999 §5.1]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
//! [RFC 9000 §10.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3
//!
//! [RFC 9000 §5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
use core::{
    borrow::Borrow,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};
use snafu::Snafu;
use subtle::ConstantTimeEq as _;

pub mod codec;

/// A QUIC version 1 connection ID: 0 to 20 bytes.
///
/// Equality, ordering and hashing are those of [`ConnectionId::as_bytes`],
/// so a connection ID can be looked up by a byte slice through
/// [`Borrow<[u8]>`](Borrow). The [`Default`] value is [`ConnectionId::EMPTY`].
#[derive(Clone, Copy)]
pub struct ConnectionId {
    pub(crate) len: u8,
    pub(crate) bytes: [u8; Self::MAX_LEN],
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

    /// The length as a [`ConnectionIdLength`].
    pub const fn length(&self) -> ConnectionIdLength {
        ConnectionIdLength(self.len)
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

/// The length of a QUIC version 1 connection ID: 0 to
/// [`ConnectionId::MAX_LEN`] bytes.
///
/// Equality, ordering and hashing are those of the number of bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionIdLength(u8);

impl ConnectionIdLength {
    /// The length of the zero-length connection ID.
    pub const ZERO: Self = Self(0);

    /// The length of `length` bytes.
    ///
    /// This is the `const` form of `ConnectionIdLength::try_from(length)`.
    ///
    /// # Errors
    ///
    /// [`ConnectionIdLengthError`] if `length` exceeds
    /// [`ConnectionId::MAX_LEN`].
    pub const fn new(length: usize) -> Result<Self, ConnectionIdLengthError> {
        if length > ConnectionId::MAX_LEN {
            return Err(ConnectionIdLengthError { length });
        }
        Ok(Self(length as u8))
    }

    /// The length in bytes.
    pub const fn get(self) -> usize {
        self.0 as usize
    }

    /// Whether this is the length of the zero-length connection ID.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl TryFrom<usize> for ConnectionIdLength {
    type Error = ConnectionIdLengthError;

    /// Accepts lengths up to [`ConnectionId::MAX_LEN`]; see
    /// [`ConnectionIdLength::new`].
    fn try_from(length: usize) -> Result<Self, Self::Error> {
        Self::new(length)
    }
}

/// The value of the one-byte length field that precedes a connection ID in
/// long headers and frames.
impl From<ConnectionIdLength> for u8 {
    fn from(length: ConnectionIdLength) -> Self {
        length.0
    }
}

impl From<ConnectionIdLength> for usize {
    fn from(length: ConnectionIdLength) -> Self {
        length.get()
    }
}

/// Formats the number of bytes, as in `ConnectionIdLength(8)`.
impl fmt::Debug for ConnectionIdLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConnectionIdLength({})", self.0)
    }
}

/// A connection ID of 1 to 20 bytes.
///
/// It compares, orders and hashes as the [`ConnectionId`] it wraps, and
/// therefore as its bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonEmptyCid(ConnectionId);

impl NonEmptyCid {
    /// Returns `id` as a non-empty connection ID.
    ///
    /// This is the `const` form of `NonEmptyCid::try_from(id)`.
    ///
    /// # Errors
    ///
    /// [`EmptyCidError`] for the zero-length connection ID.
    pub const fn new(id: ConnectionId) -> Result<Self, EmptyCidError> {
        if id.is_empty() {
            Err(EmptyCidError)
        } else {
            Ok(Self(id))
        }
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
        Ok(Self::new(ConnectionId::new(bytes)?)?)
    }
}

impl TryFrom<ConnectionId> for NonEmptyCid {
    type Error = EmptyCidError;

    /// Accepts a non-empty connection ID; see [`NonEmptyCid::new`].
    fn try_from(id: ConnectionId) -> Result<Self, Self::Error> {
        Self::new(id)
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

/// The connection ID passed to [`NonEmptyCid::new`] is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("connection ID is empty"))]
pub struct EmptyCidError;

/// Failures of converting a byte slice to a [`NonEmptyCid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum NonEmptyCidError {
    /// The connection ID has no bytes.
    #[snafu(transparent)]
    Empty {
        /// The rejected empty connection ID.
        source: EmptyCidError,
    },
    /// The bytes are too long for a connection ID.
    #[snafu(transparent)]
    Length {
        /// The rejected length.
        source: ConnectionIdLengthError,
    },
}

/// A connection ID as the version-independent long header carries it: 0 to
/// 255 bytes ([RFC 8999 §5.1]).
///
/// Equality, ordering and hashing are those of [`RawConnectionId::as_bytes`].
/// Convert it with [`ConnectionId::try_from`] to apply the QUIC version 1
/// limit of 20 bytes.
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

impl From<ConnectionId> for RawConnectionId {
    fn from(id: ConnectionId) -> Self {
        let mut raw = Self::EMPTY;
        raw.bytes[..id.len()].copy_from_slice(id.as_bytes());
        raw.len = id.len;
        raw
    }
}

impl TryFrom<RawConnectionId> for ConnectionId {
    type Error = ConnectionIdLengthError;

    /// Applies the QUIC version 1 limit; see [`ConnectionId::new`].
    fn try_from(id: RawConnectionId) -> Result<Self, Self::Error> {
        Self::new(id.as_bytes())
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("connection ID of {length} bytes exceeds the long header maximum of 255 bytes"))]
pub struct RawConnectionIdLengthError {
    /// The rejected length.
    pub length: usize,
}

/// A Stateless Reset Token: the 16 bytes that end a stateless reset for the
/// connection ID it was issued with ([RFC 9000 §10.3]).
///
/// Tokens compare in constant time: how long a comparison takes does not
/// depend on their bytes ([RFC 9000 §10.3.1]).
///
/// [RFC 9000 §10.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3
/// [RFC 9000 §10.3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.1
#[derive(Clone, Copy, Eq)]
pub struct StatelessResetToken([u8; Self::LEN]);

impl StatelessResetToken {
    /// The length of a token in bytes.
    pub const LEN: usize = 16;

    /// The token with the bytes `bytes`.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes of the token.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl PartialEq for StatelessResetToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// Hashes the bytes, consistently with equality.
impl Hash for StatelessResetToken {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl From<[u8; StatelessResetToken::LEN]> for StatelessResetToken {
    fn from(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }
}

impl From<StatelessResetToken> for [u8; StatelessResetToken::LEN] {
    fn from(token: StatelessResetToken) -> Self {
        token.0
    }
}

impl AsRef<[u8]> for StatelessResetToken {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Formats the bytes as lowercase hexadecimal, as in
/// `StatelessResetToken(00112233445566778899aabbccddeeff)`.
impl fmt::Debug for StatelessResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatelessResetToken({})", Hex(&self.0))
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
