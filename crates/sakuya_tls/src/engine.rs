//! What the server's and the client's handshake engines share: the CRYPTO
//! byte streams they read and write, and how a handshake fails.
//!
//! A handshake engine is a `nitori_call` operation, run as a `LentCall`.
//! What it owns for the whole handshake, such as the backend and the
//! capabilities of its role, are its arguments; what the connection
//! provides, it receives as receivers lent on every poll:
//!
//! - `input`, a [`CryptoInput`]: the CRYPTO bytes the peer sent, at the
//!   current [`CryptoLevel`];
//! - `output`, a [`CryptoOutput`]: the CRYPTO bytes to send, at the current
//!   level;
//! - `transport`: the transport parameters, through synchronous methods of
//!   the role's own capability.
//!
//! The engine reads and writes the bytes of the current level only, and
//! moves each stream to the next level as a separate step (RFC 9001
//! §4.1.3). It hands over traffic secrets and the completion of the
//! handshake as the items it yields, and ends with a [`HandshakeError`]
//! when the handshake fails.
//!
//! `#[capability]` generates `{Trait}Ext` and `{Trait}ViewExt` for each
//! receiver capability, with the methods the trait documents.

// The generated extension traits have no documentation comments; the
// module documentation above describes them.
#![allow(missing_docs)]

use crate::{
    alert::{AlertDescription, CallsForAlert},
    message::codec::ReadHandshakeMessageError,
};
use core::{convert::Infallible, pin::Pin};
use nitori_call::capability;
use nitori_io::{
    Read, Write,
    calls::{ReadArrayError, WriteAllError},
    error::WriteZero,
};
use snafu::Snafu;

/// An encryption level that carries CRYPTO frames: Initial, Handshake or
/// 1-RTT. 0-RTT packets carry none (RFC 9000 §12.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CryptoLevel {
    /// Initial.
    Initial,
    /// Handshake.
    Handshake,
    /// 1-RTT.
    OneRtt,
}

/// The CRYPTO bytes a handshake engine receives: those of the current
/// level, read with [`Read`].
///
/// Reading waits for bytes that have not arrived. A level begins as
/// [`CryptoLevel::Initial`] and moves forward with [`CryptoInput::move_to`].
#[capability]
pub trait CryptoInput: Read {
    /// A failure to move to a level.
    type LevelError;

    /// Moves to `level`: later reads return its bytes.
    ///
    /// # Errors
    ///
    /// As the implementation documents; RFC 9001 §4.1.3 makes it an error
    /// when bytes of the level being left remain unread.
    fn move_to<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        level: CryptoLevel,
    ) -> Result<(), Self::LevelError>
    where
        Self: 'v;
}

/// The CRYPTO bytes a handshake engine sends: those of the current level,
/// written with [`Write`].
///
/// A level begins as [`CryptoLevel::Initial`] and moves forward with
/// [`CryptoOutput::move_to`]; what was written before stays at its level.
#[capability]
pub trait CryptoOutput: Write {
    /// Moves to `level`: later writes go to it.
    fn move_to<'v>(view: Pin<&mut Self::ReceiverView<'v>>, level: CryptoLevel)
    where
        Self: 'v;
}

/// How a handshake fails: with an alert, or with a failure of the
/// connection's receivers.
///
/// `F` is the role's failure, which names its alert; in QUIC the alert
/// closes the connection with the error code `0x0100` plus the alert
/// description (RFC 9001 §4.8). `E` is the error of the connection, which
/// the receivers report, such as CRYPTO_BUFFER_EXCEEDED or
/// TRANSPORT_PARAMETER_ERROR.
#[derive(Debug, Snafu)]
pub enum HandshakeError<F, E> {
    /// The handshake ends with the alert `source` calls for.
    #[snafu(display("handshake failed"))]
    Alert {
        /// The failure.
        source: F,
    },
    /// A receiver of the connection failed.
    #[snafu(display("connection failed during the handshake"))]
    Transport {
        /// The connection's error.
        source: E,
    },
}

impl<F: CallsForAlert, E> HandshakeError<F, E> {
    /// The alert to close with, or `None` when a receiver failed.
    pub fn alert(&self) -> Option<AlertDescription> {
        match self {
            Self::Alert { source } => Some(source.alert()),
            Self::Transport { .. } => None,
        }
    }
}

impl<F, E> HandshakeError<F, E> {
    /// The role's failure, if the handshake ends with an alert.
    pub fn failure(&self) -> Option<&F> {
        match self {
            Self::Alert { source } => Some(source),
            Self::Transport { .. } => None,
        }
    }

    /// The connection's error, if a receiver failed.
    pub fn transport(&self) -> Option<&E> {
        match self {
            Self::Alert { .. } => None,
            Self::Transport { source } => Some(source),
        }
    }
}

/// Splits a failure to read a handshake message into the part that calls
/// for an alert and the receiver's own failure.
pub(crate) fn split_read<E>(
    error: ReadHandshakeMessageError<E>,
) -> Result<ReadHandshakeMessageError<Infallible>, E> {
    fn array<E>(error: ReadArrayError<E>) -> Result<ReadArrayError<Infallible>, E> {
        match error {
            ReadArrayError::Incomplete { source } => Ok(ReadArrayError::Incomplete { source }),
            ReadArrayError::Receiver { source, .. } => Err(source),
        }
    }
    Ok(match error {
        ReadHandshakeMessageError::Header { source } => ReadHandshakeMessageError::Header {
            source: array(source)?,
        },
        ReadHandshakeMessageError::Body { source } => ReadHandshakeMessageError::Body {
            source: array(source)?,
        },
        ReadHandshakeMessageError::Unexpected { source } => {
            ReadHandshakeMessageError::Unexpected { source }
        }
        ReadHandshakeMessageError::TooLong { source } => {
            ReadHandshakeMessageError::TooLong { source }
        }
    })
}

/// Splits a failure to write into the sink that stopped and the receiver's
/// own failure.
pub(crate) fn split_write<E>(error: WriteAllError<E>) -> Result<WriteZero, E> {
    match error {
        WriteAllError::WriteZero { source } => Ok(source),
        WriteAllError::Receiver { source, .. } => Err(source),
    }
}

/// Encodes a message with a synchronous writer on a vector.
pub(crate) fn encode(
    len: usize,
    write: impl FnOnce(&mut Vec<u8>) -> Result<(), WriteAllError<Infallible>>,
) -> bytes::Bytes {
    let mut encoded = Vec::with_capacity(len);
    match write(&mut encoded) {
        Ok(()) => {}
        Err(error) => match error.host_error() {
            Some(never) => match *never {},
            // invariant: a vector accepts every byte.
            None => unreachable!("{error}"),
        },
    }
    debug_assert_eq!(encoded.len(), len);
    bytes::Bytes::from(encoded)
}
