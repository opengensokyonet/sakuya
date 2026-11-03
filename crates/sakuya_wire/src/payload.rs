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
//!
//! A chunk never holds more bytes than requested: that is the contract of
//! `nitori_io`'s `ReadChunk`, and the length of a field relies on it, such
//! as a STREAM frame whose Length field must state the length of its data.
//! A receiver that returns a longer chunk breaks the contract, and reading
//! panics.
use core::num::NonZeroUsize;
use nitori_call::ReceiverAccess;
use nitori_io::{ReadChunk, ReadChunkExt as _, error::Incomplete};
use snafu::{IntoError, ResultExt, Snafu};

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
/// A field that is read has exactly `length` bytes.
///
/// # Panics
///
/// If the receiver returns a chunk longer than `length`, which breaks the
/// `ReadChunk` contract of `nitori_io`.
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
    let first = io
        .read_chunk(maximum)
        .await
        .context(read_payload_error::ReceiverSnafu { completed: 0usize })?;
    let Some(first) = first else {
        return Err(Incomplete {
            expected: length,
            completed: 0,
        }
        .into());
    };
    let received = bytes::Buf::remaining(&first);
    assert!(
        received <= length,
        "the receiver broke the `ReadChunk` contract of nitori_io: a chunk holds at most \
         `maximum` bytes, but a request for {length} bytes returned {received}"
    );
    let Some(rest) = NonZeroUsize::new(length - received) else {
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
    let first = io
        .read_chunk(NonZeroUsize::MAX)
        .await
        .context(read_payload_error::ReceiverSnafu { completed: 0usize })?;
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

#[cfg(test)]
mod tests {
    use crate::frame::{Extensions, codec::ReadFrameHostExt as _};
    use bytes::{Buf, BufMut};
    use core::{
        convert::Infallible,
        num::NonZeroUsize,
        pin::Pin,
        task::{Context, Poll},
    };
    use nitori_io::{Read, ReadChunk};

    /// A source that breaks the `ReadChunk` contract: each chunk holds the
    /// rest of the source, whatever the maximum.
    struct Overlong(&'static [u8]);

    nitori_call::family_receiver!(impl [] for Overlong);

    impl Read for Overlong {
        type Error = Infallible;

        fn poll_read<'visit, Output: BufMut + ?Sized>(
            host: Pin<&mut Self::ReceiverView<'visit>>,
            _: &mut Context<'_>,
            mut destination: &mut Output,
        ) -> Poll<Result<usize, Self::Error>>
        where
            Self: 'visit,
        {
            let source = &mut host.get_pin_mut().get_mut().0;
            let count = source.remaining().min(destination.remaining_mut());
            BufMut::put(&mut destination, source.take(count));
            Poll::Ready(Ok(count))
        }
    }

    impl ReadChunk for Overlong {
        type Chunk = &'static [u8];

        fn poll_read_chunk<'visit>(
            host: Pin<&mut Self::ReceiverView<'visit>>,
            _: &mut Context<'_>,
            _: NonZeroUsize,
        ) -> Poll<Result<Option<Self::Chunk>, Self::Error>>
        where
            Self: 'visit,
        {
            let source = &mut host.get_pin_mut().get_mut().0;
            Poll::Ready(Ok((!source.is_empty()).then(|| core::mem::take(source))))
        }
    }

    #[test]
    fn a_source_that_keeps_the_contract_reads_the_field() {
        // The same CRYPTO frame from a byte slice, which keeps the contract.
        let mut input = &[0x06, 0x00, 0x02, 1, 2, 3, 4][..];
        assert!(input.sync_read_frame_unpin(Extensions::NONE).is_ok());
        assert_eq!(input, [3, 4]);
    }

    #[test]
    #[should_panic(expected = "the receiver broke the `ReadChunk` contract")]
    fn a_chunk_longer_than_requested_panics() {
        // A CRYPTO frame with two bytes of data, and two bytes after it that
        // the source returns in the same chunk.
        let mut source = Overlong(&[0x06, 0x00, 0x02, 1, 2, 3, 4]);
        let _ = source.sync_read_frame_unpin(Extensions::NONE);
    }
}
