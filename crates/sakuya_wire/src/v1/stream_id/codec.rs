//! Reading and writing [`StreamId`] as `nitori_call` operations.
//!
//! A stream ID is encoded as a variable-length integer, so the operations
//! fail as [`read_var_int`](crate::var_int::codec::read_var_int) and
//! [`write_var_int`](crate::var_int::codec::write_var_int) do.
//!
//! ```
//! use sakuya_wire::v1::stream_id::{
//!     Directionality, Initiator, StreamId,
//!     codec::{ReadStreamIdHostExt as _, WriteStreamIdHostExt as _},
//! };
//!
//! let id = StreamId::new(Initiator::Server, Directionality::Unidirectional, 2).unwrap();
//! let mut output = Vec::new();
//! output.sync_write_stream_id_unpin(id).unwrap();
//! assert_eq!(output, [0x0b]);
//! assert_eq!(output.as_slice().sync_read_stream_id_unpin().unwrap(), id);
//! ```
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::StreamId;
use crate::var_int::codec::{
    ReadVarIntError, ReadVarIntExt as _, WriteVarIntError, WriteVarIntExt as _,
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::prelude::*;

/// Reads one stream ID.
///
/// # Errors
///
/// [`ReadVarIntError`] if the variable-length integer cannot be read.
#[call(sync)]
pub async fn read_stream_id<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<StreamId, ReadVarIntError<F::Error>> {
    io.read_var_int().await.map(StreamId::from_var_int)
}

/// Writes the shortest encoding of `id` completely.
///
/// # Errors
///
/// [`WriteVarIntError`] if the receiver stops accepting bytes or fails.
#[call(sync)]
pub async fn write_stream_id<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    id: StreamId,
) -> Result<(), WriteVarIntError<F::Error>> {
    io.write_var_int(id.get()).await
}
