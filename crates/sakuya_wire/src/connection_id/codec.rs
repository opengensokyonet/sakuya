//! Reading length-prefixed connection IDs.
//!
//! Long headers carry a connection ID as a one-byte length followed by that
//! many bytes. [`read_raw_connection_id`] reads it as the
//! version-independent header does, up to 255 bytes. The package
//! `sakuya_wire_v1` reads and writes the form of QUIC version 1, which is
//! limited to 20 bytes.
use super::RawConnectionId;
use crate::source::{incomplete, read_array};
use bytes::Buf;
use nitori_io::error::IncompleteError;
use snafu::{ResultExt, Snafu};

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
