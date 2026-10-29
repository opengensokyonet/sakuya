//! Variable-length payload fields read as one chunk of the source.
//!
//! The data of STREAM, CRYPTO and DATAGRAM frames, NEW_TOKEN tokens,
//! CONNECTION_CLOSE reason phrases, header tokens and the values of unknown
//! transport parameters are read with `nitori_io`'s `ReadChunk` capability:
//! each field is one chunk of the source, of the source's `ReadChunk::Chunk`
//! type. A byte slice source yields subslices of itself and a `Bytes` source
//! yields `Bytes` that share its storage, so reading copies no payload. An
//! empty field is the chunk type's [`Default`] value.
//!
//! A source whose chunks can be shorter than requested while more bytes
//! follow, such as one that copies into bounded storage, cannot deliver a
//! field longer than its chunks; that is reported as
//! [`ReadPayloadError::Split`].
use core::num::NonZeroUsize;
use nitori_call::ReceiverAccess;
use nitori_io::{ReadChunk, ReadChunkExt as _, error::Incomplete};
use snafu::{IntoError, Snafu};

/// Failures of reading a payload field.
#[derive(Debug, Snafu)]
#[snafu(module(read_payload_error), visibility(pub(crate)))]
pub enum ReadPayloadError<E> {
    /// The source ended before the field was complete.
    #[snafu(transparent)]
    Incomplete {
        /// The shortfall, counted over the field.
        source: Incomplete,
    },
    /// The source delivered the field in more than one chunk.
    #[snafu(display("payload arrived in more than one chunk, the first of {received} bytes"))]
    Split {
        /// The length of the field, or `None` for a field that extends to
        /// the end of the source.
        expected: Option<usize>,
        /// The length of the first chunk.
        received: usize,
    },
    /// The receiver failed.
    #[snafu(display("payload read failed after {completed} bytes"))]
    Receiver {
        /// The receiver's error.
        source: E,
        /// Bytes of the field read before the failure.
        completed: usize,
    },
}

impl<E> ReadPayloadError<E> {
    /// Whether the source ended before the field was complete.
    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }

    /// The receiver's error, if the failure came from the receiver.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Receiver { source, .. } => Some(source),
            Self::Incomplete { .. } | Self::Split { .. } => None,
        }
    }
}

/// Reads a field of `length` bytes as one chunk.
///
/// When the first chunk is shorter, a second read tells an ended source
/// ([`ReadPayloadError::Incomplete`]) from one that splits the field
/// ([`ReadPayloadError::Split`]); bytes read before a failure stay consumed.
pub(crate) async fn read_payload<F, A>(
    io: &mut A,
    length: usize,
) -> Result<F::Chunk, ReadPayloadError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    let Some(maximum) = NonZeroUsize::new(length) else {
        return Ok(F::Chunk::default());
    };
    let first = io.read_chunk(maximum).await.map_err(|source| {
        read_payload_error::ReceiverSnafu { completed: 0usize }.into_error(source)
    })?;
    let Some(first) = first else {
        return Err(Incomplete {
            expected: length,
            completed: 0,
        }
        .into());
    };
    let received = bytes::Buf::remaining(&first);
    let Some(rest) = NonZeroUsize::new(length.saturating_sub(received)) else {
        return Ok(first);
    };
    match io.read_chunk(rest).await {
        Ok(None) => Err(Incomplete {
            expected: length,
            completed: received,
        }
        .into()),
        Ok(Some(_)) => read_payload_error::SplitSnafu {
            expected: Some(length),
            received,
        }
        .fail(),
        Err(source) => Err(read_payload_error::ReceiverSnafu {
            completed: received,
        }
        .into_error(source)),
    }
}

/// Reads the rest of the source as one chunk; an ended source gives an
/// empty field.
pub(crate) async fn read_payload_to_end<F, A>(
    io: &mut A,
) -> Result<F::Chunk, ReadPayloadError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    let first = io.read_chunk(NonZeroUsize::MAX).await.map_err(|source| {
        read_payload_error::ReceiverSnafu { completed: 0usize }.into_error(source)
    })?;
    let Some(first) = first else {
        return Ok(F::Chunk::default());
    };
    let received = bytes::Buf::remaining(&first);
    match io.read_chunk(NonZeroUsize::MAX).await {
        Ok(None) => Ok(first),
        Ok(Some(_)) => read_payload_error::SplitSnafu {
            expected: None,
            received,
        }
        .fail(),
        Err(source) => Err(read_payload_error::ReceiverSnafu {
            completed: received,
        }
        .into_error(source)),
    }
}
