//! Reading and writing length-prefixed connection IDs as `nitori_call`
//! operations.
//!
//! Long headers and NEW_CONNECTION_ID carry a connection ID as a one-byte
//! length followed by that many bytes. [`read_raw_connection_id`] reads it
//! as the version-independent header does, up to 255 bytes;
//! [`read_connection_id`] applies the QUIC version 1 limit of 20 bytes and
//! rejects a longer length before reading the bytes. [`write_connection_id`]
//! writes the same form.
//!
//! Each function is also an operation struct with `{Name}Ext` on receiver
//! accesses inside other operations and `{Name}HostExt` on call executors,
//! including the `sync_` methods for receivers that never wait.
//!
//! ```
//! use sakuya_wire::connection_id::{
//!     ConnectionId,
//!     codec::{ReadConnectionIdHostExt as _, WriteConnectionIdHostExt as _},
//! };
//!
//! let id = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0]).unwrap();
//! let mut output = Vec::new();
//! output.sync_write_connection_id_unpin(id).unwrap();
//! assert_eq!(output, [4, 0x83, 0x94, 0xc8, 0xf0]);
//!
//! let mut input = output.as_slice();
//! assert_eq!(input.sync_read_connection_id_unpin().unwrap(), id);
//! assert!(input.is_empty());
//! ```
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{ConnectionId, ConnectionIdLength, ConnectionIdLengthError, RawConnectionId};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{
    calls::{ReadArrayError, ReadExactError, WriteAllError},
    prelude::*,
};
use snafu::{ResultExt, Snafu};

/// Reads a one-byte length and a connection ID of that length, at most 20
/// bytes.
///
/// # Errors
///
/// [`ReadConnectionIdError::LengthField`] if the length cannot be read,
/// [`ReadConnectionIdError::Length`] for a length above 20, before reading
/// further, and [`ReadConnectionIdError::Bytes`] if the bytes cannot be read.
#[call(sync)]
pub async fn read_connection_id<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<ConnectionId, ReadConnectionIdError<F::Error>> {
    let [length] = io
        .read_array::<1>()
        .await
        .context(read_connection_id_error::LengthFieldSnafu)?;
    let length = ConnectionIdLength::new(usize::from(length))?;
    let mut id = ConnectionId::EMPTY;
    let mut destination = &mut id.bytes[..length.get()];
    io.read_exact(&mut destination, length.get())
        .await
        .context(read_connection_id_error::BytesSnafu)?;
    id.len = u8::from(length);
    Ok(id)
}

/// Failures that [`read_connection_id`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_connection_id_error), visibility(pub(crate)))]
pub enum ReadConnectionIdError<E> {
    /// The length byte could not be read.
    #[snafu(display("connection ID length read failed"))]
    LengthField {
        /// The failure of reading the length.
        source: ReadArrayError<E>,
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
        /// The failure of reading the bytes.
        source: ReadExactError<E>,
    },
}

impl<E> ReadConnectionIdError<E> {
    /// Whether the source ended within the connection ID.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::LengthField { source } => matches!(source, ReadArrayError::Incomplete { .. }),
            Self::Bytes { source } => matches!(source, ReadExactError::Incomplete { .. }),
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
#[call(sync)]
pub async fn read_raw_connection_id<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<RawConnectionId, ReadRawConnectionIdError<F::Error>> {
    let [length] = io
        .read_array::<1>()
        .await
        .context(read_raw_connection_id_error::LengthFieldSnafu)?;
    let length = usize::from(length);
    let mut id = RawConnectionId::EMPTY;
    let mut destination = &mut id.bytes[..length];
    io.read_exact(&mut destination, length)
        .await
        .context(read_raw_connection_id_error::BytesSnafu)?;
    id.len = length as u8;
    Ok(id)
}

/// Failures that [`read_raw_connection_id`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_raw_connection_id_error), visibility(pub(crate)))]
pub enum ReadRawConnectionIdError<E> {
    /// The length byte could not be read.
    #[snafu(display("connection ID length read failed"))]
    LengthField {
        /// The failure of reading the length.
        source: ReadArrayError<E>,
    },
    /// The bytes of the connection ID could not be read.
    #[snafu(display("connection ID read failed"))]
    Bytes {
        /// The failure of reading the bytes.
        source: ReadExactError<E>,
    },
}

impl<E> ReadRawConnectionIdError<E> {
    /// Whether the source ended within the connection ID.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::LengthField { source } => matches!(source, ReadArrayError::Incomplete { .. }),
            Self::Bytes { source } => matches!(source, ReadExactError::Incomplete { .. }),
        }
    }
}

/// Writes the one-byte length of `id` and its bytes.
///
/// Acceptance by the receiver does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteAllError`] if the receiver stops accepting bytes or fails; bytes
/// accepted before stay written.
#[call(sync)]
pub async fn write_connection_id<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    id: ConnectionId,
) -> Result<(), WriteAllError<F::Error>> {
    let length = [u8::from(id.length())];
    io.write_all(bytes::Buf::chain(&length[..], id.as_bytes()))
        .await
}
