//! Reading and writing [`VarInt`] as `nitori_call` operations.
//!
//! [`read_var_int`] and [`write_var_int`] are also the operation structs
//! [`ReadVarInt`] and [`WriteVarInt`], with `ReadVarIntExt` and
//! `WriteVarIntExt` on receiver accesses inside other operations and
//! `ReadVarIntHostExt` and `WriteVarIntHostExt` on call executors, including
//! the `sync_` methods for receivers that never wait, such as byte slices
//! and `Bytes`. On those, a source that ends early is an
//! [`ReadVarIntError::Incomplete`] failure. Constructing an operation
//! performs no IO.
//!
//! ```
//! use sakuya_wire::var_int::{
//!     VarInt,
//!     codec::{ReadVarIntHostExt as _, WriteVarIntHostExt as _},
//! };
//!
//! let mut output = Vec::new();
//! output.sync_write_var_int_unpin(VarInt::from(15293u16)).unwrap();
//! assert_eq!(output, [0x7b, 0xbd]);
//!
//! let mut input = &[0x7b, 0xbd, 0x25][..];
//! assert_eq!(input.sync_read_var_int_unpin().unwrap(), VarInt::from(15293u16));
//! assert_eq!(input, [0x25]); // The next integer has not been read.
//!
//! // Encodings longer than necessary are accepted.
//! let mut input = &[0x40, 0x25][..];
//! assert_eq!(input.sync_read_var_int_unpin().unwrap(), VarInt::from(37u8));
//!
//! // A source that ends within the encoding is incomplete.
//! let mut input = &[0x9d, 0x7f][..];
//! let error = input.sync_read_var_int_unpin().unwrap_err();
//! assert_eq!(error.completed(), 2);
//! ```
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::VarInt;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{
    calls::{ReadArrayError, WriteAllError},
    error::{Incomplete, WriteZero},
    prelude::*,
};
use snafu::{IntoError, Snafu};

/// Reads one variable-length integer.
///
/// Reads the first byte, then exactly the remaining bytes of the length it
/// announces, and nothing after them. Encodings longer than necessary are
/// accepted.
///
/// # Errors
///
/// [`ReadVarIntError::Incomplete`] if the source ends before the encoding is
/// complete, and [`ReadVarIntError::Receiver`] if the receiver fails. Bytes
/// read before a failure stay consumed; [`ReadVarIntError::completed`]
/// reports how many there were.
#[call(sync)]
pub async fn read_var_int<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<VarInt, ReadVarIntError<F::Error>> {
    read_var_int_counted(io).await.map(|(value, _)| value)
}

/// Reads one variable-length integer as [`read_var_int`] does, and returns
/// it with the length of its encoding.
pub(crate) async fn read_var_int_counted<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<(VarInt, usize), ReadVarIntError<F::Error>> {
    let [first] = io
        .read_array::<1>()
        .await
        .map_err(|error| ReadVarIntError::after(error, 0, 1))?;
    let encoded_len = VarInt::encoded_len_of(first);
    let value = match encoded_len {
        1 => VarInt::from_encoding(first, &[]),
        2 => VarInt::from_encoding(first, &read_rest::<1, F, A>(io, encoded_len).await?),
        4 => VarInt::from_encoding(first, &read_rest::<3, F, A>(io, encoded_len).await?),
        _ => VarInt::from_encoding(first, &read_rest::<7, F, A>(io, encoded_len).await?),
    };
    Ok((value, encoded_len))
}

/// Reads the `LENGTH` bytes that follow the first byte of an encoding.
async fn read_rest<const LENGTH: usize, F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    encoded_len: usize,
) -> Result<[u8; LENGTH], ReadVarIntError<F::Error>> {
    io.read_array::<LENGTH>()
        .await
        .map_err(|error| ReadVarIntError::after(error, 1, encoded_len))
}

/// Failures that [`read_var_int`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_var_int_error), visibility(pub(crate)))]
pub enum ReadVarIntError<E> {
    /// The source ended before the encoding was complete.
    ///
    /// `expected` is the encoded length once the first byte has been read,
    /// and 1 if the source ended before it.
    #[snafu(transparent)]
    Incomplete {
        /// The shortfall, counted over the whole encoding.
        source: Incomplete,
    },
    /// The receiver failed.
    #[snafu(display("variable-length integer read failed after {completed} bytes"))]
    Receiver {
        /// The receiver's error.
        source: E,
        /// Bytes of the encoding read before the failure.
        completed: usize,
    },
}

impl<E> ReadVarIntError<E> {
    /// Whether the source ended before the encoding was complete.
    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }

    /// Bytes of the encoding read before the failure.
    pub fn completed(&self) -> usize {
        match self {
            Self::Incomplete { source } => source.completed,
            Self::Receiver { completed, .. } => *completed,
        }
    }

    /// The receiver's error, if the failure came from the receiver.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Receiver { source, .. } => Some(source),
            Self::Incomplete { .. } => None,
        }
    }

    /// Restates a failure of reading part of an encoding that starts `offset`
    /// bytes into it, counting progress over the whole encoding.
    fn after(error: ReadArrayError<E>, offset: usize, encoded_len: usize) -> Self {
        match error {
            ReadArrayError::Incomplete { source } => Self::Incomplete {
                source: Incomplete {
                    expected: encoded_len,
                    completed: offset + source.completed,
                },
            },
            ReadArrayError::Receiver { source, completed } => read_var_int_error::ReceiverSnafu {
                completed: offset + completed,
            }
            .into_error(source),
        }
    }
}

/// Writes the shortest encoding of `value` completely.
///
/// Acceptance by the receiver does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteVarIntError::WriteZero`] if the receiver accepts nothing from a
/// nonempty remainder, and [`WriteVarIntError::Receiver`] if it fails. Bytes
/// accepted before a failure stay written; [`WriteVarIntError::completed`]
/// reports how many there were.
#[call(sync)]
pub async fn write_var_int<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    value: VarInt,
) -> Result<(), WriteVarIntError<F::Error>> {
    let (encoding, encoded_len) = value.to_encoding();
    io.write_all(&encoding[..encoded_len]).await?;
    Ok(())
}

/// Failures that [`write_var_int`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(write_var_int_error), visibility(pub(crate)))]
pub enum WriteVarIntError<E> {
    /// The receiver accepted nothing from a nonempty remainder.
    #[snafu(transparent)]
    WriteZero {
        /// The bytes accepted before the receiver stopped accepting.
        source: WriteZero,
    },
    /// The receiver failed.
    #[snafu(display("variable-length integer write failed after {completed} bytes"))]
    Receiver {
        /// The receiver's error.
        source: E,
        /// Bytes of the encoding accepted before the failure.
        completed: usize,
    },
}

impl<E> WriteVarIntError<E> {
    /// Bytes of the encoding accepted before the failure.
    pub fn completed(&self) -> usize {
        match self {
            Self::WriteZero { source } => source.completed,
            Self::Receiver { completed, .. } => *completed,
        }
    }

    /// The receiver's error, if the failure came from the receiver.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Receiver { source, .. } => Some(source),
            Self::WriteZero { .. } => None,
        }
    }
}

impl<E> From<WriteAllError<E>> for WriteVarIntError<E> {
    fn from(error: WriteAllError<E>) -> Self {
        match error {
            WriteAllError::WriteZero { source } => source.into(),
            WriteAllError::Receiver { source, completed } => {
                write_var_int_error::ReceiverSnafu { completed }.into_error(source)
            }
        }
    }
}
