//! Sources and sinks that behave unlike byte slices: they wait between
//! bytes, take one byte at a time, fail, or fill up. The readers and writers
//! must give the same results on them as on byte slices.
use bytes::{Buf, BufMut};
use nitori_call::family_receiver;
use nitori_io::{Read, ReadChunk, Write};
use std::{
    convert::Infallible,
    io,
    num::NonZeroUsize,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};

/// Polls `future` to completion, waking itself whenever it waits.
pub fn run<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
}

/// A source that waits before every read, and hands over one byte per read
/// and chunks of up to the requested size.
pub struct Waiting<'a> {
    /// The bytes not yet read.
    pub source: &'a [u8],
    ready: bool,
}

impl<'a> Waiting<'a> {
    pub fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            ready: false,
        }
    }

    /// Alternates between waiting, after waking the task, and being ready.
    fn turn(&mut self, cx: &mut Context<'_>) -> bool {
        self.ready = !self.ready;
        if !self.ready {
            return true;
        }
        cx.waker().wake_by_ref();
        false
    }
}

family_receiver!(impl ['a] for Waiting<'a>);

impl Read for Waiting<'_> {
    type Error = Infallible;

    fn poll_read<'visit, Output: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        destination: &mut Output,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if !this.turn(cx) {
            return Poll::Pending;
        }
        if destination.remaining_mut() == 0 || this.source.is_empty() {
            return Poll::Ready(Ok(0));
        }
        destination.put_u8(this.source[0]);
        this.source = &this.source[1..];
        Poll::Ready(Ok(1))
    }
}

impl<'a> ReadChunk for Waiting<'a> {
    type Chunk = &'a [u8];

    fn poll_read_chunk<'visit>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<Self::Chunk>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if !this.turn(cx) {
            return Poll::Pending;
        }
        if this.source.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let (chunk, rest) = this.source.split_at(maximum.get().min(this.source.len()));
        this.source = rest;
        Poll::Ready(Ok(Some(chunk)))
    }
}

/// The failure of a [`Failing`] source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceFailed;

impl std::fmt::Display for SourceFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the source failed")
    }
}

impl std::error::Error for SourceFailed {}

/// A source that hands over one byte per read and fails once it has handed
/// over `limit` bytes.
pub struct Failing<'a> {
    source: &'a [u8],
    limit: usize,
}

impl<'a> Failing<'a> {
    pub fn new(source: &'a [u8], limit: usize) -> Self {
        Self { source, limit }
    }
}

family_receiver!(impl ['a] for Failing<'a>);

impl Read for Failing<'_> {
    type Error = SourceFailed;

    fn poll_read<'visit, Output: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _: &mut Context<'_>,
        destination: &mut Output,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if this.limit == 0 {
            return Poll::Ready(Err(SourceFailed));
        }
        if destination.remaining_mut() == 0 || this.source.is_empty() {
            return Poll::Ready(Ok(0));
        }
        destination.put_u8(this.source[0]);
        this.source = &this.source[1..];
        this.limit -= 1;
        Poll::Ready(Ok(1))
    }
}

impl<'a> ReadChunk for Failing<'a> {
    type Chunk = &'a [u8];

    fn poll_read_chunk<'visit>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<Self::Chunk>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if this.limit == 0 {
            return Poll::Ready(Err(SourceFailed));
        }
        if this.source.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let (chunk, rest) = this
            .source
            .split_at(maximum.get().min(this.source.len()).min(this.limit));
        this.source = rest;
        this.limit -= chunk.len();
        Poll::Ready(Ok(Some(chunk)))
    }
}

/// A sink that waits before every write and takes one byte per write.
#[derive(Default)]
pub struct WaitingSink {
    /// The bytes accepted so far.
    pub written: Vec<u8>,
    ready: bool,
}

family_receiver!(impl [] for WaitingSink);

impl Write for WaitingSink {
    type Error = Infallible;

    fn poll_write<'visit, Input: Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        input: &mut Input,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        this.ready = !this.ready;
        if this.ready {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if !input.has_remaining() {
            return Poll::Ready(Ok(0));
        }
        this.written.push(input.get_u8());
        Poll::Ready(Ok(1))
    }
}

/// A `std::io::Write` sink that takes one byte per write, for use through
/// `nitori_io::bridge::Std`.
#[derive(Default)]
pub struct OneByte(pub Vec<u8>);

impl io::Write for OneByte {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match buffer.first() {
            Some(&byte) => {
                self.0.push(byte);
                Ok(1)
            }
            None => Ok(0),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
