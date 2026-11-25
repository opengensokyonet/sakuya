//! Decoding and encoding on the sources and sinks of `nitori_io`
//! ([`stream`](crate::stream)), on sources and sinks that may wait or fail
//! as well as on byte slices.

use super::{BOUNDARIES, RFC_EXAMPLES, var_int};
use crate::stream::{ReadVarIntError, VarIntCompleted, WriteVarIntError};
use crate::{VarInt, VarIntField, VarIntWidth};
use core::{
    future::Future,
    num::NonZeroUsize,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use nitori_call::{ReceiverAccess, call};
use nitori_codec::prelude::*;
use nitori_io::{Combine, Read, ReadSegment, Write, WriteSegment, bridge::Std, calls::ReadValue};
use std::io;

#[test]
fn decoding_a_field_keeps_the_width() {
    let cases: [(&[u8], u64, VarIntWidth); 4] = [
        (&[0x25], 37, VarIntWidth::One),
        (&[0x40, 0x25], 37, VarIntWidth::Two),
        (&[0x80, 0x00, 0x00, 0x25], 37, VarIntWidth::Four),
        (&[0xc0, 0, 0, 0, 0, 0, 0, 0x25], 37, VarIntWidth::Eight),
    ];
    for (encoding, value, width) in cases {
        let input = [encoding, &[0xff][..]].concat();
        let mut rest = &input[..];
        let field = rest.sync_decode_unpin::<VarIntField<VarInt>>().unwrap();
        assert_eq!(
            (field.get(), field.width()),
            (VarInt::new(value).unwrap(), width)
        );
        assert_eq!(rest, [0xff], "{encoding:02x?}");
    }
    let mut truncated = &[0x80, 0x00][..];
    let error = truncated
        .sync_decode_unpin::<VarIntField<VarInt>>()
        .unwrap_err();
    assert!(error.is_incomplete());
    assert_eq!(error.completed(), 2);
}

#[test]
fn reports_each_truncated_length() {
    let cases: [(&[u8], usize); 4] = [
        (&[0x40], 2),
        (&[0x9d, 0x7f, 0x3e], 4),
        (&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8], 8),
        (&[0x7b], 2),
    ];
    for (encoding, encoded_len) in cases {
        let mut input = encoding;
        let error = input.sync_decode_unpin::<VarInt>().unwrap_err();
        let ReadVarIntError::Incomplete { source: incomplete } = &error else {
            panic!("expected Incomplete, got {error:?}");
        };
        assert_eq!(
            (incomplete.expected(), incomplete.completed()),
            (encoded_len, encoding.len()),
            "{encoding:02x?}"
        );
        assert!(error.is_incomplete());
    }
}

#[test]
fn encoding_into_a_full_slice_reports_progress() {
    let mut storage = [0xaa; 3];
    let mut output = &mut storage[..];
    let error = output.sync_encode_unpin(var_int(494_878_333)).unwrap_err();
    assert!(matches!(error, WriteVarIntError::WriteZero { .. }));
    assert_eq!(error.completed(), 3);
    assert_eq!(storage, [0x9d, 0x7f, 0x3e]);

    let mut storage = [0; 2];
    let mut output = &mut storage[..];
    output.sync_encode_unpin(var_int(15_293)).unwrap();
    assert!(output.is_empty());
    assert_eq!(storage, [0x7b, 0xbd]);
}

#[test]
fn decoding_reads_exactly_one_encoding() {
    for (encoding, value) in RFC_EXAMPLES.into_iter().chain(BOUNDARIES) {
        let input = [encoding, &[0x25]].concat();
        let mut source = input.as_slice();
        assert_eq!(
            source.sync_decode_unpin::<VarInt>().unwrap(),
            var_int(value)
        );
        assert_eq!(source, [0x25]);
    }
}

/// A source that yields one byte per read and fails once it is exhausted.
struct Trickle<'a> {
    bytes: &'a [u8],
}

impl io::Read for Trickle<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some((&first, rest)) = self.bytes.split_first() else {
            return Err(io::Error::other("source failed"));
        };
        if buffer.is_empty() {
            return Ok(0);
        }
        buffer[0] = first;
        self.bytes = rest;
        Ok(1)
    }
}

#[test]
fn decoding_accumulates_short_reads() {
    let (encoding, value) = RFC_EXAMPLES[0];
    let mut source = Std::new(Trickle { bytes: encoding });
    assert_eq!(
        source.sync_decode_unpin::<VarInt>().unwrap(),
        var_int(value)
    );
}

#[test]
fn decoding_reports_an_ended_source() {
    let mut source = &[][..];
    let error = source.sync_decode_unpin::<VarInt>().unwrap_err();
    let ReadVarIntError::Incomplete { source: incomplete } = &error else {
        panic!("expected Incomplete, got {error:?}");
    };
    assert_eq!((incomplete.expected(), incomplete.completed()), (1, 0));
    assert_eq!(error.completed(), 0);

    let mut source = &[0x9d, 0x7f][..];
    let error = source.sync_decode_unpin::<VarInt>().unwrap_err();
    let ReadVarIntError::Incomplete { source: incomplete } = &error else {
        panic!("expected Incomplete, got {error:?}");
    };
    assert_eq!((incomplete.expected(), incomplete.completed()), (4, 2));
    assert!(error.host_error().is_none());
    assert!(source.is_empty());
}

#[test]
fn decoding_keeps_the_receiver_error() {
    let mut source = Std::new(Trickle {
        bytes: &[0xc2, 0x19, 0x7c],
    });
    let error = source.sync_decode_unpin::<VarInt>().unwrap_err();
    assert!(matches!(
        error,
        ReadVarIntError::Receiver { completed, .. } if completed.get() == 3
    ));
    assert_eq!(error.completed(), 3);
    assert_eq!(error.host_error().unwrap().to_string(), "source failed");
    assert_eq!(
        error.to_string(),
        "variable-length integer read failed after 3 bytes"
    );

    let mut source = Std::new(Trickle { bytes: &[] });
    let error = source.sync_decode_unpin::<VarInt>().unwrap_err();
    assert!(matches!(
        error,
        ReadVarIntError::Receiver { completed, .. } if completed.get() == 0
    ));

    // A failure before the last byte of the longest encoding.
    let mut source = Std::new(Trickle {
        bytes: &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8],
    });
    let error = source.sync_decode_unpin::<VarInt>().unwrap_err();
    assert!(matches!(
        error,
        ReadVarIntError::Receiver { completed, .. } if completed.get() == 7
    ));
}

#[test]
fn completed_bytes_stay_below_the_longest_encoding() {
    for count in 0..8 {
        let completed = VarIntCompleted::new(count).unwrap();
        assert_eq!(completed.get(), count);
        assert_eq!(completed.to_string(), count.to_string());
    }
    for count in [8, 9, usize::MAX] {
        assert_eq!(VarIntCompleted::new(count), None, "{count}");
    }
}

#[test]
fn encoding_writes_the_shortest_encoding() {
    for (encoding, value) in RFC_EXAMPLES.into_iter().chain(BOUNDARIES) {
        let mut output = Vec::new();
        output.sync_encode_unpin(var_int(value)).unwrap();
        assert_eq!(output, encoding);
    }
}

#[test]
fn encoding_a_field_writes_the_width() {
    let cases: [(&[u8], u64, VarIntWidth); 4] = [
        (&[0x25], 37, VarIntWidth::One),
        (&[0x40, 0x25], 37, VarIntWidth::Two),
        (&[0x80, 0x00, 0x00, 0x25], 37, VarIntWidth::Four),
        (&[0xc0, 0, 0, 0, 0, 0, 0, 0x25], 37, VarIntWidth::Eight),
    ];
    for (encoding, value, width) in cases {
        let field = VarIntField::new(var_int(value), width).unwrap();
        let mut output = Vec::new();
        output.sync_encode_unpin(field).unwrap();
        assert_eq!(output, encoding);
        let mut input = output.as_slice();
        assert_eq!(
            input.sync_decode_unpin::<VarIntField<VarInt>>().unwrap(),
            field
        );
    }
}

#[test]
fn encoding_a_field_reports_failures_with_progress() {
    let field = VarIntField::new(var_int(37), VarIntWidth::Eight).unwrap();
    let mut sink = Std::new(Narrow {
        accepted: Vec::new(),
        room: 3,
        fail: true,
    });
    let error = sink.sync_encode_unpin(field).unwrap_err();
    assert_eq!(error.completed(), 3);
    assert_eq!(error.host_error().unwrap().to_string(), "sink failed");
    assert_eq!(sink.into_inner().accepted, [0xc0, 0, 0]);
}

/// A sink that accepts up to `room` bytes, one per write, then fails or stops
/// accepting.
struct Narrow {
    accepted: Vec<u8>,
    room: usize,
    fail: bool,
}

impl io::Write for Narrow {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.accepted.len() == self.room {
            return if self.fail {
                Err(io::Error::other("sink failed"))
            } else {
                Ok(0)
            };
        }
        let Some(&first) = input.first() else {
            return Ok(0);
        };
        self.accepted.push(first);
        Ok(1)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn encoding_accumulates_short_writes() {
    let (encoding, value) = RFC_EXAMPLES[1];
    let mut sink = Std::new(Narrow {
        accepted: Vec::new(),
        room: usize::MAX,
        fail: false,
    });
    sink.sync_encode_unpin(var_int(value)).unwrap();
    assert_eq!(sink.into_inner().accepted, encoding);
}

#[test]
fn encoding_reports_failures_with_progress() {
    let value = var_int(RFC_EXAMPLES[0].1);
    let mut sink = Std::new(Narrow {
        accepted: Vec::new(),
        room: 5,
        fail: true,
    });
    let error = sink.sync_encode_unpin(value).unwrap_err();
    assert!(matches!(
        error,
        WriteVarIntError::Receiver { completed, .. } if completed.get() == 5
    ));
    assert_eq!(error.completed(), 5);
    assert_eq!(error.host_error().unwrap().to_string(), "sink failed");
    assert_eq!(
        error.to_string(),
        "variable-length integer write failed after 5 bytes"
    );

    let mut sink = Std::new(Narrow {
        accepted: Vec::new(),
        room: 2,
        fail: false,
    });
    let error = sink.sync_encode_unpin(value).unwrap_err();
    assert!(matches!(error, WriteVarIntError::WriteZero { .. }));
    assert_eq!(error.completed(), 2);
    assert!(error.host_error().is_none());
}

/// Metadata that records the tag of each read, in order.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tags(Vec<u8>);

impl nitori_io::Combine for Tags {
    fn combine(mut self, next: Self) -> Self {
        self.0.extend(next.0);
        self
    }
}

/// A source that yields one byte per read, tagged with its position.
struct Tagged {
    bytes: Vec<u8>,
    position: u8,
}

nitori_call::family_receiver!(impl [] for Tagged);

impl nitori_io::Read for Tagged {
    type Error = !;
    type Metadata = Tags;

    fn poll_read<'v, Output: bytes::BufMut + ?Sized>(
        host: core::pin::Pin<&mut Self::ReceiverView<'v>>,
        _: &mut core::task::Context<'_>,
        destination: &mut Output,
    ) -> core::task::Poll<Result<Option<nitori_io::ReadSegment<Tags>>, !>>
    where
        Self: 'v,
    {
        let source = host.get_pin_mut().get_mut();
        if source.bytes.is_empty() || !destination.has_remaining_mut() {
            return core::task::Poll::Ready(Ok(None));
        }
        destination.put_u8(source.bytes.remove(0));
        let metadata = Tags(vec![source.position]);
        source.position += 1;
        core::task::Poll::Ready(Ok(Some(nitori_io::ReadSegment {
            count: core::num::NonZeroUsize::MIN,
            metadata,
        })))
    }
}

#[test]
fn decoding_from_a_source_with_metadata_merges_it() {
    let mut source = Tagged {
        bytes: vec![0x7b, 0xbd, 0x40, 0x25, 0xff],
        position: 0,
    };
    let ReadValue { value, metadata } = source
        .sync_decode_unpin::<ReadValue<VarInt, Tags>>()
        .unwrap();
    assert_eq!((value, metadata), (var_int(15_293), Tags(vec![0, 1])));
    let ReadValue { value, metadata } = source
        .sync_decode_unpin::<ReadValue<VarIntField<VarInt>, Tags>>()
        .unwrap();
    assert_eq!(
        (value.get(), value.width(), metadata),
        (var_int(37), VarIntWidth::Two, Tags(vec![2, 3]))
    );
    assert_eq!(source.bytes, [0xff]);
}

#[test]
fn encoded_length_is_that_of_the_encoding() {
    let complete = |future: core::pin::Pin<&mut dyn Future<Output = Result<u64, !>>>| {
        let core::task::Poll::Ready(Ok(len)) = future.poll(&mut core::task::Context::from_waker(
            core::task::Waker::noop(),
        )) else {
            unreachable!("the length is known at once")
        };
        len
    };
    for (encoding, value) in RFC_EXAMPLES.into_iter().chain(BOUNDARIES) {
        let len = encoding.len() as u64;
        assert_eq!(
            complete(core::pin::pin!(EncodedLen::encoded_len(&mut var_int(
                value
            )))),
            len
        );
    }
    let mut field = VarIntField::new(var_int(37), VarIntWidth::Eight).unwrap();
    assert_eq!(
        complete(core::pin::pin!(EncodedLen::encoded_len(&mut field))),
        8
    );
}

#[test]
fn a_truncated_source_with_metadata_fails_as_one_without() {
    let mut source = Tagged {
        bytes: vec![0x7b],
        position: 0,
    };
    let error = source
        .sync_decode_unpin::<ReadValue<VarInt, Tags>>()
        .unwrap_err();
    let ReadVarIntError::Incomplete { source: incomplete } = &error else {
        panic!("expected Incomplete, got {error:?}");
    };
    assert_eq!((incomplete.expected(), incomplete.completed()), (2, 1));
}

/// Polls `future` with a waker that does nothing until it is ready, and
/// counts the times it was not.
fn drive<F: Future>(future: F) -> (F::Output, usize) {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let mut pending = 0;
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return (output, pending),
            Poll::Pending => pending += 1,
        }
    }
}

/// A source that waits before each byte and yields one per read.
struct Hesitant {
    bytes: Vec<u8>,
    ready: bool,
}

nitori_call::family_receiver!(impl [] for Hesitant);

impl Read for Hesitant {
    type Error = !;
    type Metadata = ();

    fn poll_read<'v, Output: bytes::BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        destination: &mut Output,
    ) -> Poll<Result<Option<ReadSegment<()>>, !>>
    where
        Self: 'v,
    {
        let source = host.get_pin_mut().get_mut();
        if !source.ready {
            source.ready = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        source.ready = false;
        if source.bytes.is_empty() || !destination.has_remaining_mut() {
            return Poll::Ready(Ok(None));
        }
        destination.put_u8(source.bytes.remove(0));
        Poll::Ready(Ok(Some(ReadSegment {
            count: NonZeroUsize::MIN,
            metadata: (),
        })))
    }
}

#[test]
fn decoding_waits_between_bytes() {
    let mut source = Hesitant {
        bytes: vec![0x7b, 0xbd, 0x40, 0x25, 0xff],
        ready: false,
    };
    let (value, pending) = drive(source.decode_unpin::<VarInt>());
    assert_eq!((value.unwrap(), pending), (var_int(15_293), 2));
    let (field, pending) = drive(source.decode_unpin::<VarIntField<VarInt>>());
    let field = field.unwrap();
    assert_eq!(
        (field.get(), field.width(), pending),
        (var_int(37), VarIntWidth::Two, 2)
    );
    assert_eq!(source.bytes, [0xff], "nothing after the encodings is read");
}

/// A sink that waits before each write, takes one byte, and reports the
/// byte's position.
struct Ledger {
    accepted: Vec<u8>,
    ready: bool,
}

nitori_call::family_receiver!(impl [] for Ledger);

impl Write for Ledger {
    type Error = !;
    type Report = Tags;

    fn poll_write<'v, Input: bytes::Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        input: &mut Input,
    ) -> Poll<Result<Option<WriteSegment<Tags>>, !>>
    where
        Self: 'v,
    {
        let sink = host.get_pin_mut().get_mut();
        if !sink.ready {
            sink.ready = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        sink.ready = false;
        if !input.has_remaining() {
            return Poll::Ready(Ok(None));
        }
        let position = u8::try_from(sink.accepted.len()).unwrap();
        sink.accepted.push(input.get_u8());
        Poll::Ready(Ok(Some(WriteSegment {
            count: NonZeroUsize::MIN,
            report: Tags(vec![position]),
        })))
    }
}

#[test]
fn encoding_waits_between_bytes_and_merges_the_reports() {
    let mut sink = Ledger {
        accepted: Vec::new(),
        ready: false,
    };
    let (report, pending) = drive(sink.encode_unpin(var_int(15_293)));
    assert_eq!((report.unwrap(), pending), (Tags(vec![0, 1]), 2));
    let field = VarIntField::new(var_int(37), VarIntWidth::Four).unwrap();
    let (report, pending) = drive(sink.encode_unpin(field));
    assert_eq!((report.unwrap(), pending), (Tags(vec![2, 3, 4, 5]), 4));
    // A value read with metadata writes only the value.
    let read = ReadValue {
        value: var_int(37),
        metadata: Tags(vec![9]),
    };
    let (report, _) = drive(sink.encode_unpin(read));
    assert_eq!(report.unwrap(), Tags(vec![6]));
    assert_eq!(sink.accepted, [0x7b, 0xbd, 0x80, 0, 0, 0x25, 0x25]);
}

/// Two integers decoded inside an operation, through its access.
#[call(sync)]
async fn decode_two<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<[VarInt; 2], ReadVarIntError<F::Error>> {
    let first = io.decode::<VarInt>().await?;
    let second = io.decode::<VarIntField<VarInt>>().await?;
    Ok([first, second.get()])
}

/// Two integers encoded inside an operation, through its access, with the
/// reports merged.
#[call(sync)]
async fn encode_two<F: Write<Report: Combine>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    first: VarInt,
    second: VarIntField<VarInt>,
) -> Result<F::Report, WriteVarIntError<F::Error>> {
    let report = io.encode(first).await?;
    Ok(report.combine(io.encode(second).await?))
}

#[test]
fn operations_decode_and_encode_through_their_access() {
    let mut input = &[0x7b, 0xbd, 0x40, 0x25, 0xff][..];
    assert_eq!(
        input.sync_decode_two_unpin().unwrap(),
        [var_int(15_293), var_int(37)]
    );
    assert_eq!(input, [0xff]);

    let mut sink = Ledger {
        accepted: Vec::new(),
        ready: false,
    };
    let field = VarIntField::new(var_int(37), VarIntWidth::Two).unwrap();
    let (report, _) = drive(sink.encode_two_unpin(var_int(15_293), field));
    assert_eq!(report.unwrap(), Tags(vec![0, 1, 2, 3]));
    assert_eq!(sink.accepted, [0x7b, 0xbd, 0x40, 0x25]);
}
