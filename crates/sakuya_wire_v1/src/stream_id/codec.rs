//! Reading and writing [`StreamId`].
//!
//! A stream ID is encoded as a variable-length integer, so the functions
//! fail as [`read_var_int`] and
//! [`write_var_int`] do.
//!
//! ```
//! use sakuya_wire_v1::stream_id::{
//!     Directionality, Initiator, StreamId,
//!     codec::{read_stream_id, write_stream_id},
//! };
//!
//! let id = StreamId::new(Initiator::Server, Directionality::Unidirectional, 2).unwrap();
//! let mut output = Vec::new();
//! write_stream_id(&mut output, id);
//! assert_eq!(output, [0x0b]);
//! assert_eq!(read_stream_id(&mut output.as_slice()).unwrap(), id);
//! ```
use super::StreamId;
use crate::var_int::codec::{read_var_int, write_var_int};
use bytes::{Buf, BufMut};
use nitori_io::error::IncompleteError;

/// Reads one stream ID.
///
/// # Errors
///
/// [`IncompleteError`] if the source ends within the variable-length
/// integer.
pub fn read_stream_id(src: &mut impl Buf) -> Result<StreamId, IncompleteError> {
    read_var_int(src).map(StreamId::from_var_int)
}

/// Writes the shortest encoding of `id`.
///
/// # Panics
///
/// If `dst` has no room for the encoding, as [`BufMut`] does.
pub fn write_stream_id(dst: &mut impl BufMut, id: StreamId) {
    write_var_int(dst, id.get());
}
