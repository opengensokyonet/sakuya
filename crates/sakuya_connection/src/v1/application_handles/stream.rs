//! The handles of a stream: the stream writer ([`StreamWriter`]) and the
//! stream reader ([`StreamReader`]), what they can do besides reading and
//! writing bytes ([`StreamWrite`], [`StreamRead`]), and what a writer sends
//! its data with.
//!
//! The bytes go through nitori_io only: a writer is a `Write` host, a
//! reader a `Read` and `ReadChunk` host, and operations such as
//! `write_all` or `read_exact` come from nitori_io's `calls`. What a stream
//! does on close, reset, stop, flush and acknowledgment is the contract of
//! the stream's sending and receiving parts in `sakuya_stream`; the traits
//! here state no other.
//!
//! A writer carries the send parameters and destination its writes copy
//! onto their data: [`NoSendOptions`] as opened or accepted, a
//! [`SendOptions`] once set ([`StreamWriter::with_send_options`]). Without
//! one it writes only when the parameters have a default and the
//! destination can be had from [`AnyActiveLinkPath`].

use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Buf;
use sakuya_stream::{
    connection::LayerEndedError,
    receive::stop::StopError,
    send::{
        StreamResetError,
        finish::{CloseError, ResetError},
        write::{FlushError, WriteError, WriteReport},
    },
    send_options::{NoSendOptions, SendOptions, destination::AnyActiveLinkPath},
};
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use snafu::Snafu;

/// What a stream's sending part can be asked besides taking bytes
/// (`StreamWrite`): the write primitive with the parameters and destination
/// of the data, close, reset, flush and waiting for every byte and the end
/// to be acknowledged.
///
/// The semantics are those of the sending part (`sakuya_stream::send`):
/// a write takes a prefix of the input, or waits; it hands the data and its
/// reliable delivery to the transport, which does not mean it was sent.
pub trait StreamWrite {
    /// The parameters application data is sent with.
    type Parameters;
    /// Where application data is sent.
    type Destination;
    /// This endpoint's reason for closing, which the layer's end carries.
    type CloseCause;
    /// The reason the termination policy gives for a write limit.
    type WriteLimitReason;

    /// Takes as much of `input` as the stream's and the connection's limits
    /// allow now, copying `parameters` and `destination` onto it, and
    /// advances `input` past it; `Pending` while nothing can be taken, with
    /// the waker of `cx` woken when that may change. An empty `input` is
    /// taken at once, with zero bytes.
    ///
    /// # Errors
    ///
    /// The sending part's [`WriteError`]; nothing is taken then.
    #[allow(clippy::type_complexity)]
    fn poll_write_with<B: Buf + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &Self::Parameters,
        destination: &Self::Destination,
    ) -> Poll<Result<WriteReport, WriteError<Self::WriteLimitReason, Self::CloseCause>>>;

    /// [`poll_write_with`](Self::poll_write_with) with the default
    /// parameters, to any active link path.
    ///
    /// # Errors
    ///
    /// As [`poll_write_with`](Self::poll_write_with).
    #[allow(clippy::type_complexity)]
    fn poll_write<B: Buf + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        input: &mut B,
    ) -> Poll<Result<WriteReport, WriteError<Self::WriteLimitReason, Self::CloseCause>>>
    where
        Self::Parameters: Default,
        Self::Destination: From<AnyActiveLinkPath>,
    {
        self.poll_write_with(
            cx,
            input,
            &Self::Parameters::default(),
            &AnyActiveLinkPath.into(),
        )
    }

    /// Ends the stream normally after what was written.
    ///
    /// # Errors
    ///
    /// The sending part's [`CloseError`].
    fn close(&mut self) -> Result<(), CloseError<Self::CloseCause>>;

    /// Resets the stream with `code`.
    ///
    /// # Errors
    ///
    /// The sending part's [`ResetError`].
    fn reset(&mut self, code: ApplicationErrorCode) -> Result<(), ResetError<Self::CloseCause>>;

    /// Done once every write that succeeded before it was handed to the
    /// transport; it waits neither for the data to be sent nor for it to be
    /// acknowledged. An implementation that hands writes over in batches
    /// keeps at most a bounded amount before it does.
    ///
    /// # Errors
    ///
    /// The sending part's [`FlushError`].
    fn flush(&mut self) -> impl Future<Output = Result<(), FlushError<Self::CloseCause>>>;

    /// Done once every byte and the end of the stream were acknowledged by
    /// the peer: after [`close`](Self::close).
    ///
    /// # Errors
    ///
    /// [`AllAcknowledgedError`] once the stream was reset or the layer
    /// ended before.
    fn all_acknowledged(
        &mut self,
    ) -> impl Future<Output = Result<(), AllAcknowledgedError<Self::CloseCause>>>;
}

/// [`StreamWrite::all_acknowledged`] cannot be done; `C` is this
/// endpoint's reason for closing.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
pub enum AllAcknowledgedError<C> {
    /// The stream was reset.
    #[snafu(transparent)]
    Reset {
        /// The reset in effect.
        source: StreamResetError,
    },
    /// The layer ended.
    #[snafu(transparent)]
    LayerEnded {
        /// How it ended.
        source: LayerEndedError<C>,
    },
}

/// What a stream's receiving part can be asked besides giving bytes
/// (`StreamRead`): to have the peer stop sending.
///
/// The semantics are those of the receiving part (`sakuya_stream::receive`).
pub trait StreamRead {
    /// This endpoint's reason for closing, which the layer's end carries.
    type CloseCause;

    /// Asks the peer to stop sending, with `code` (STOP_SENDING).
    ///
    /// # Errors
    ///
    /// The receiving part's [`StopError`].
    fn stop(&mut self, code: ApplicationErrorCode) -> Result<(), StopError<Self::CloseCause>>;
}

/// A borrowed share writes as the share does.
impl<E: StreamWrite + ?Sized> StreamWrite for &mut E {
    type Parameters = E::Parameters;
    type Destination = E::Destination;
    type CloseCause = E::CloseCause;
    type WriteLimitReason = E::WriteLimitReason;

    fn poll_write_with<B: Buf + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &E::Parameters,
        destination: &E::Destination,
    ) -> Poll<Result<WriteReport, WriteError<E::WriteLimitReason, E::CloseCause>>> {
        (**self).poll_write_with(cx, input, parameters, destination)
    }

    fn close(&mut self) -> Result<(), CloseError<E::CloseCause>> {
        (**self).close()
    }

    fn reset(&mut self, code: ApplicationErrorCode) -> Result<(), ResetError<E::CloseCause>> {
        (**self).reset(code)
    }

    fn flush(&mut self) -> impl Future<Output = Result<(), FlushError<E::CloseCause>>> {
        (**self).flush()
    }

    fn all_acknowledged(
        &mut self,
    ) -> impl Future<Output = Result<(), AllAcknowledgedError<E::CloseCause>>> {
        (**self).all_acknowledged()
    }
}

// ---- the writer ----

/// A stream writer (`StreamWriter`): the application's handle of a
/// stream's sending part.
///
/// `E` is the capability of the sending part — the way it reaches the
/// part, through the shared connection or apart from it, with the pointer
/// to the writer's credential — or a borrow of one
/// ([`borrow_with_send_options`]); `O` the send parameters and destination
/// its writes copy onto their data, [`NoSendOptions`] until set. It can be
/// cloned where `E` can, as with a shared credential: several writers of
/// the same stream write in whatever order they are called, and each that
/// waits is woken. Once the last
/// holder of the credential drops its writer, the stream is given up; what
/// follows is the sending part's termination policy's.
///
/// [`borrow_with_send_options`]: Self::borrow_with_send_options
#[derive(Clone)]
pub struct StreamWriter<E, O> {
    pub(crate) share: E,
    options: O,
}

impl<E> StreamWriter<E, NoSendOptions> {
    /// The writer of the share `share`, with no send options.
    pub(crate) fn new(share: E) -> Self {
        Self {
            share,
            options: NoSendOptions,
        }
    }
}

impl<E, O> StreamWriter<E, O> {
    /// The writer of what `map` makes of its share, with the same options.
    pub(crate) fn map_share<F>(self, map: impl FnOnce(E) -> F) -> StreamWriter<F, O> {
        StreamWriter {
            share: map(self.share),
            options: self.options,
        }
    }
}

impl<E: StreamWrite, O> StreamWriter<E, O> {
    /// This writer with `parameters` and `destination` for its writes from
    /// now on.
    pub fn with_send_options(
        self,
        parameters: E::Parameters,
        destination: E::Destination,
    ) -> StreamWriter<E, SendOptions<E::Parameters, E::Destination>> {
        StreamWriter {
            share: self.share,
            options: SendOptions::new(parameters, destination),
        }
    }

    /// A writer of the same share with `parameters` and `destination`, for
    /// some writes; this one keeps its own afterwards.
    pub fn borrow_with_send_options(
        &mut self,
        parameters: E::Parameters,
        destination: E::Destination,
    ) -> StreamWriter<&mut E, SendOptions<E::Parameters, E::Destination>> {
        StreamWriter {
            share: &mut self.share,
            options: SendOptions::new(parameters, destination),
        }
    }
}

impl<E, P, D> StreamWriter<E, SendOptions<P, D>> {
    /// The send parameters and destination of the writes from now on; what
    /// was written keeps those it was written with.
    pub fn send_options_mut(&mut self) -> &mut SendOptions<P, D> {
        &mut self.options
    }
}

/// The writer writes through its share; [`poll_write_with`] is given the
/// parameters and destination of each call, not the writer's own.
///
/// [`poll_write_with`]: StreamWrite::poll_write_with
impl<E: StreamWrite, O> StreamWrite for StreamWriter<E, O> {
    type Parameters = E::Parameters;
    type Destination = E::Destination;
    type CloseCause = E::CloseCause;
    type WriteLimitReason = E::WriteLimitReason;

    fn poll_write_with<B: Buf + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &E::Parameters,
        destination: &E::Destination,
    ) -> Poll<Result<WriteReport, WriteError<E::WriteLimitReason, E::CloseCause>>> {
        self.share
            .poll_write_with(cx, input, parameters, destination)
    }

    fn close(&mut self) -> Result<(), CloseError<E::CloseCause>> {
        self.share.close()
    }

    fn reset(&mut self, code: ApplicationErrorCode) -> Result<(), ResetError<E::CloseCause>> {
        self.share.reset(code)
    }

    fn flush(&mut self) -> impl Future<Output = Result<(), FlushError<E::CloseCause>>> {
        self.share.flush()
    }

    fn all_acknowledged(
        &mut self,
    ) -> impl Future<Output = Result<(), AllAcknowledgedError<E::CloseCause>>> {
        self.share.all_acknowledged()
    }
}

impl<E, O: fmt::Debug> fmt::Debug for StreamWriter<E, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamWriter")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

nitori_call::family_receiver!(impl [E, O] for StreamWriter<E, O>);

/// One write of `writer` with `parameters` and `destination`, counted as
/// nitori_io counts it: the bytes `input` was advanced by.
#[allow(clippy::type_complexity)]
fn poll_nitori_write<E: StreamWrite, B: Buf + ?Sized>(
    share: &mut E,
    cx: &mut Context<'_>,
    input: &mut B,
    parameters: &E::Parameters,
    destination: &E::Destination,
) -> Poll<Result<usize, WriteError<E::WriteLimitReason, E::CloseCause>>> {
    let before = input.remaining();
    share
        .poll_write_with(cx, input, parameters, destination)
        .map_ok(|report| {
            let taken = before - input.remaining();
            debug_assert_eq!(
                u64::try_from(taken).ok(),
                Some(report.new_bytes.get()),
                "the report counts the bytes taken"
            );
            taken
        })
}

/// A writer with send options writes with them.
impl<E, P, D> nitori_io::Write for StreamWriter<E, SendOptions<P, D>>
where
    E: StreamWrite<Parameters = P, Destination = D> + Unpin,
    P: Unpin,
    D: Unpin,
{
    type Error = WriteError<E::WriteLimitReason, E::CloseCause>;

    fn poll_write<'visit, Input: Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        input: &mut Input,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        poll_nitori_write(
            &mut this.share,
            cx,
            input,
            this.options.parameters(),
            this.options.destination(),
        )
    }
}

/// A writer without send options writes with the default parameters, to
/// any active link path, where the parameters have a default and the
/// destination can be had from [`AnyActiveLinkPath`].
impl<E> nitori_io::Write for StreamWriter<E, NoSendOptions>
where
    E: StreamWrite<Parameters: Default, Destination: From<AnyActiveLinkPath>> + Unpin,
{
    type Error = WriteError<E::WriteLimitReason, E::CloseCause>;

    fn poll_write<'visit, Input: Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        input: &mut Input,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        poll_nitori_write(
            &mut this.share,
            cx,
            input,
            &E::Parameters::default(),
            &AnyActiveLinkPath.into(),
        )
    }
}

// ---- the reader ----

/// A stream reader (`StreamReader`): the application's handle of a
/// stream's receiving part.
///
/// `E` is the capability of the receiving part, as a writer's is of the
/// sending part. The bytes are read through nitori_io's `Read` and
/// `ReadChunk`, which the stream set implements for its readers. It can be
/// cloned where `E` can: several readers of the same stream each take what
/// they read, and each that waits is woken. Once the last holder of the credential drops its reader, the
/// reading is given up; what follows is the receiving part's termination
/// policy's.
#[derive(Clone)]
pub struct StreamReader<E> {
    pub(crate) share: E,
}

impl<E> StreamReader<E> {
    /// The reader of the share `share`.
    pub(crate) fn new(share: E) -> Self {
        Self { share }
    }
}

/// The reader stops through its share.
impl<E: StreamRead> StreamRead for StreamReader<E> {
    type CloseCause = E::CloseCause;

    fn stop(&mut self, code: ApplicationErrorCode) -> Result<(), StopError<E::CloseCause>> {
        self.share.stop(code)
    }
}

impl<E> fmt::Debug for StreamReader<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamReader").finish_non_exhaustive()
    }
}

nitori_call::family_receiver!(impl [E] for StreamReader<E>);
