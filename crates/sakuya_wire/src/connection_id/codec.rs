//! Reading and writing length-prefixed connection IDs.
//!
//! Long headers and NEW_CONNECTION_ID carry a connection ID as a one-byte
//! length followed by that many bytes. [`read_raw_connection_id`] reads it
//! as the version-independent header does, up to 255 bytes;
//! [`read_connection_id`] applies the QUIC version 1 limit of 20 bytes and
//! rejects a longer length before reading the bytes. [`write_connection_id`]
//! writes the same form.
//!
//! ```
//! use sakuya_wire::connection_id::{
//!     ConnectionId,
//!     codec::{read_connection_id, write_connection_id},
//! };
//!
//! let id = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0]).unwrap();
//! let mut output = Vec::new();
//! write_connection_id(&mut output, id);
//! assert_eq!(output, [4, 0x83, 0x94, 0xc8, 0xf0]);
//!
//! let mut input = output.as_slice();
//! assert_eq!(read_connection_id(&mut input).unwrap(), id);
//! assert!(input.is_empty());
//! ```
use super::{ConnectionId, ConnectionIdLength, ConnectionIdLengthError, RawConnectionId};
use crate::source::{incomplete, read_array};
use bytes::{Buf, BufMut};
use nitori_io::error::IncompleteError;
use snafu::{ResultExt, Snafu};

/// Reads a one-byte length and a connection ID of that length, at most 20
/// bytes.
///
/// # Errors
///
/// [`ReadConnectionIdError::LengthField`] if the length cannot be read,
/// [`ReadConnectionIdError::Length`] for a length above 20, before reading
/// further, and [`ReadConnectionIdError::Bytes`] if the bytes cannot be read.
pub fn read_connection_id(src: &mut impl Buf) -> Result<ConnectionId, ReadConnectionIdError> {
    let [length] = read_array::<1>(src).context(read_connection_id_error::LengthFieldSnafu)?;
    let length = ConnectionIdLength::new(usize::from(length))?;
    let mut id = ConnectionId::EMPTY;
    read_bytes(src, &mut id.bytes[..length.get()]).context(read_connection_id_error::BytesSnafu)?;
    id.len = u8::from(length);
    Ok(id)
}

/// Failures that [`read_connection_id`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_connection_id_error), visibility(pub(crate)))]
pub enum ReadConnectionIdError {
    /// The length byte could not be read.
    #[snafu(display("connection ID length read failed"))]
    LengthField {
        /// The shortfall: the source is empty.
        source: IncompleteError,
    },
    /// The length exceeds the QUIC version 1 maximum.
    #[snafu(transparent)]
    Length {
        /// The rejected length.
        source: ConnectionIdLengthError,
    },
    /// The bytes of the connection ID could not be read.
    #[snafu(display("connection ID read failed"))]
    Bytes {
        /// The shortfall, counted over the bytes of the connection ID.
        source: IncompleteError,
    },
}

impl ReadConnectionIdError {
    /// Whether the source ended within the connection ID.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::LengthField { .. } | Self::Bytes { .. } => true,
            Self::Length { .. } => false,
        }
    }
}

/// Reads a one-byte length and a connection ID of that length, as the
/// version-independent long header carries it.
///
/// # Errors
///
/// [`ReadRawConnectionIdError::LengthField`] if the length cannot be read and
/// [`ReadRawConnectionIdError::Bytes`] if the bytes cannot be read.
pub fn read_raw_connection_id(
    src: &mut impl Buf,
) -> Result<RawConnectionId, ReadRawConnectionIdError> {
    let [length] = read_array::<1>(src).context(read_raw_connection_id_error::LengthFieldSnafu)?;
    let length = usize::from(length);
    let mut id = RawConnectionId::EMPTY;
    read_bytes(src, &mut id.bytes[..length]).context(read_raw_connection_id_error::BytesSnafu)?;
    id.len = length as u8;
    Ok(id)
}

/// Failures that [`read_raw_connection_id`] can produce; in each the source
/// ended early.
#[derive(Debug, Snafu)]
#[snafu(module(read_raw_connection_id_error), visibility(pub(crate)))]
pub enum ReadRawConnectionIdError {
    /// The length byte could not be read.
    #[snafu(display("connection ID length read failed"))]
    LengthField {
        /// The shortfall: the source is empty.
        source: IncompleteError,
    },
    /// The bytes of the connection ID could not be read.
    #[snafu(display("connection ID read failed"))]
    Bytes {
        /// The shortfall, counted over the bytes of the connection ID.
        source: IncompleteError,
    },
}

/// Fills `destination` from `src`.
fn read_bytes(src: &mut impl Buf, destination: &mut [u8]) -> Result<(), IncompleteError> {
    if src.remaining() < destination.len() {
        return Err(incomplete(src, destination.len(), 0));
    }
    src.copy_to_slice(destination);
    Ok(())
}

/// Writes the one-byte length of `id` and its bytes.
///
/// # Panics
///
/// If `dst` has no room for the connection ID, as [`BufMut`] does.
pub fn write_connection_id(dst: &mut impl BufMut, id: ConnectionId) {
    dst.put_u8(u8::from(id.length()));
    dst.put_slice(id.as_bytes());
}
