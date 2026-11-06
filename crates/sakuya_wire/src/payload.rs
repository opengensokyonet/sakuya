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
use core::{fmt, num::NonZeroUsize};
use nitori_call::ReceiverAccess;
use nitori_io::{ReadChunk, ReadChunkExt as _, error::IncompleteError};
use snafu::{IntoError, ResultExt, Snafu};

/// Failures of reading a payload field.
#[derive(Debug, Snafu)]
#[snafu(module(read_payload_error), visibility(pub(crate)))]
pub enum ReadPayloadError<E> {
    /// The source ended before the field was complete.
    #[snafu(transparent)]
    Incomplete {
        /// The shortfall, counted over the field.
        source: IncompleteError,
    },
    /// The source delivered the field in more than one chunk.
    #[snafu(transparent)]
    Split {
        /// The broken rule.
        source: SplitError,
    },
    /// The receiver failed.
    #[snafu(display("payload read failed after {completed} bytes"))]
    Receiver {
        /// The receiver's error.
        source: E,
        /// Bytes of the field read before the failure.
        completed: PayloadCompleted,
    },
}

/// The number of bytes of a payload field read before the receiver failed.
///
/// For a field of a known length it is always below that length, since a
/// failure leaves at least one byte of the field unread; a field that
/// extends to the end of the source has no such bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PayloadCompleted {
    expected: Option<usize>,
    completed: usize,
}

impl PayloadCompleted {
    /// `completed` bytes of a field of `expected` bytes, or of a field that
    /// extends to the end of the source for `None`; `None` if `completed` is
    /// not below `expected`.
    pub const fn new(expected: Option<usize>, completed: usize) -> Option<Self> {
        if let Some(expected) = expected
            && completed >= expected
        {
            return None;
        }
        Some(Self {
            expected,
            completed,
        })
    }

    /// The length of the field, or `None` for a field that extends to the
    /// end of the source.
    pub const fn expected(self) -> Option<usize> {
        self.expected
    }

    /// The number of bytes, below [`expected`](Self::expected) when that is
    /// known.
    pub const fn completed(self) -> usize {
        self.completed
    }

    /// The bytes read before a failure within a field of `length` bytes.
    fn of_field(length: usize, completed: usize) -> Self {
        match Self::new(Some(length), completed) {
            Some(completed) => completed,
            // invariant: the receiver is asked for more bytes only while
            // bytes of the field remain.
            None => panic!("a failure within a field leaves fewer bytes than its length read"),
        }
    }

    /// The bytes read before a failure within a field that extends to the end
    /// of the source.
    const fn to_end(completed: usize) -> Self {
        Self {
            expected: None,
            completed,
        }
    }
}

/// Formats the number of bytes.
impl fmt::Display for PayloadCompleted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.completed.fmt(f)
    }
}

/// The source delivered a payload field in more than one chunk.
///
/// It is constructed only when a second chunk follows the first, so for a
/// field of a known length the first chunk is always shorter than the
/// field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("payload arrived in more than one chunk, the first of {received} bytes"))]
pub struct SplitError {
    expected: Option<usize>,
    received: usize,
}

impl SplitError {
    /// The length of the field, or `None` for a field that extends to the
    /// end of the source.
    pub const fn expected(self) -> Option<usize> {
        self.expected
    }

    /// The length of the first chunk, shorter than
    /// [`expected`](Self::expected) when that is known.
    pub const fn received(self) -> usize {
        self.received
    }
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
        .context(read_payload_error::ReceiverSnafu {
            completed: PayloadCompleted::of_field(length, 0),
        })?;
    let Some(first) = first else {
        // invariant: `length` is not zero, since `maximum` is built from it,
        // so zero bytes read is below it.
        return Err(IncompleteError::new(length, 0)
            .expect("`length` is not zero")
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
        // invariant: `received` is below `length`, since `rest` is not zero.
        Ok(None) => Err(IncompleteError::new(length, received)
            .expect("`received` is below `length`")
            .into()),
        // invariant: `received` is below `length`, since `rest` is not zero.
        Ok(Some(_)) => Err(SplitError {
            expected: Some(length),
            received,
        }
        .into()),
        Err(source) => Err(read_payload_error::ReceiverSnafu {
            completed: PayloadCompleted::of_field(length, received),
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
    let first =
        io.read_chunk(NonZeroUsize::MAX)
            .await
            .context(read_payload_error::ReceiverSnafu {
                completed: PayloadCompleted::to_end(0),
            })?;
    let Some(first) = first else {
        return Ok(F::Chunk::default());
    };
    let received = bytes::Buf::remaining(&first);
    match io.read_chunk(NonZeroUsize::MAX).await {
        Ok(None) => Ok(first),
        Ok(Some(_)) => Err(SplitError {
            expected: None,
            received,
        }
        .into()),
        Err(source) => Err(read_payload_error::ReceiverSnafu {
            completed: PayloadCompleted::to_end(received),
        }
        .into_error(source)),
    }
}

#[cfg(test)]
mod tests {
    use super::{PayloadCompleted, ReadPayloadError};
    use crate::frame::{
        Extensions,
        codec::{ReadFrameError, ReadFrameHostExt as _},
        crypto::codec::ReadCryptoFrameError,
        datagram::codec::ReadDatagramFrameError,
    };
    use bytes::{Buf, BufMut};
    use core::{
        convert::Infallible,
        fmt::Debug,
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

    /// A source that keeps the `ReadChunk` contract but delivers at most one
    /// byte per chunk.
    struct Bytewise(&'static [u8]);

    nitori_call::family_receiver!(impl [] for Bytewise);

    impl Read for Bytewise {
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

    impl ReadChunk for Bytewise {
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
            if source.is_empty() {
                return Poll::Ready(Ok(None));
            }
            let (chunk, rest) = source.split_at(1);
            *source = rest;
            Poll::Ready(Ok(Some(chunk)))
        }
    }

    /// The error of [`Failing`].
    #[derive(Debug, PartialEq, Eq)]
    struct SourceFailed;

    /// A source that keeps the `ReadChunk` contract and fails, rather than
    /// ends, once its bytes are read.
    struct Failing(&'static [u8]);

    nitori_call::family_receiver!(impl [] for Failing);

    impl Read for Failing {
        type Error = SourceFailed;

        fn poll_read<'visit, Output: BufMut + ?Sized>(
            host: Pin<&mut Self::ReceiverView<'visit>>,
            _: &mut Context<'_>,
            mut destination: &mut Output,
        ) -> Poll<Result<usize, Self::Error>>
        where
            Self: 'visit,
        {
            let source = &mut host.get_pin_mut().get_mut().0;
            if source.is_empty() {
                return Poll::Ready(Err(SourceFailed));
            }
            let count = source.remaining().min(destination.remaining_mut());
            BufMut::put(&mut destination, source.take(count));
            Poll::Ready(Ok(count))
        }
    }

    impl ReadChunk for Failing {
        type Chunk = &'static [u8];

        fn poll_read_chunk<'visit>(
            host: Pin<&mut Self::ReceiverView<'visit>>,
            _: &mut Context<'_>,
            maximum: NonZeroUsize,
        ) -> Poll<Result<Option<Self::Chunk>, Self::Error>>
        where
            Self: 'visit,
        {
            let source = &mut host.get_pin_mut().get_mut().0;
            if source.is_empty() {
                return Poll::Ready(Err(SourceFailed));
            }
            let (chunk, rest) = source.split_at(source.len().min(maximum.get()));
            *source = rest;
            Poll::Ready(Ok(Some(chunk)))
        }
    }

    /// The payload failure of reading one frame from `source`.
    fn payload_error(source: &'static [u8]) -> ReadPayloadError<Infallible> {
        data_error(Bytewise(source).sync_read_frame_unpin(Extensions::ALL))
    }

    /// The payload failure of reading one frame from `source`, which fails
    /// after its bytes.
    fn receiver_error(source: &'static [u8]) -> ReadPayloadError<SourceFailed> {
        data_error(Failing(source).sync_read_frame_unpin(Extensions::ALL))
    }

    /// The failure of reading the data of a CRYPTO or DATAGRAM frame.
    fn data_error<T: Debug, E: Debug>(result: Result<T, ReadFrameError<E>>) -> ReadPayloadError<E> {
        match result {
            Err(ReadFrameError::Crypto {
                source: ReadCryptoFrameError::Data { source },
                ..
            })
            | Err(ReadFrameError::Datagram {
                source: ReadDatagramFrameError::Data { source },
                ..
            }) => source,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_field_in_more_than_one_chunk_is_split() {
        // A CRYPTO frame with three bytes of data, delivered a byte at a time.
        let ReadPayloadError::Split { source } = payload_error(&[0x06, 0x00, 0x03, 1, 2, 3]) else {
            panic!()
        };
        assert_eq!((source.expected(), source.received()), (Some(3), 1));
        assert_eq!(
            source.to_string(),
            "payload arrived in more than one chunk, the first of 1 bytes"
        );
        // A DATAGRAM frame without a Length field extends to the end.
        let ReadPayloadError::Split { source } = payload_error(&[0x30, 1, 2]) else {
            panic!()
        };
        assert_eq!((source.expected(), source.received()), (None, 1));
    }

    #[test]
    fn completed_bytes_stay_below_a_known_length() {
        for (expected, completed) in [(Some(1), 0), (Some(3), 2), (None, 0), (None, usize::MAX)] {
            let progress = PayloadCompleted::new(expected, completed).unwrap();
            assert_eq!(
                (progress.expected(), progress.completed()),
                (expected, completed)
            );
            assert_eq!(progress.to_string(), completed.to_string());
        }
        for (expected, completed) in [(0, 0), (3, 3), (3, 4)] {
            assert_eq!(PayloadCompleted::new(Some(expected), completed), None);
        }
    }

    #[test]
    fn a_receiver_failure_keeps_the_bytes_read() {
        // A CRYPTO frame whose Length of 3 the source fails within.
        let ReadPayloadError::Receiver { source, completed } =
            receiver_error(&[0x06, 0x00, 0x03, 1])
        else {
            panic!()
        };
        assert_eq!(source, SourceFailed);
        assert_eq!((completed.expected(), completed.completed()), (Some(3), 1));
        // The source fails before the first byte of the data.
        let error = receiver_error(&[0x06, 0x00, 0x03]);
        let ReadPayloadError::Receiver { completed, .. } = &error else {
            panic!()
        };
        assert_eq!((completed.expected(), completed.completed()), (Some(3), 0));
        assert_eq!(error.to_string(), "payload read failed after 0 bytes");
        // A DATAGRAM frame without a Length field extends to the end.
        let ReadPayloadError::Receiver { completed, .. } = receiver_error(&[0x30, 1, 2]) else {
            panic!()
        };
        assert_eq!((completed.expected(), completed.completed()), (None, 2));
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
