//! What the application does with datagrams: the capability the handle of
//! an established layer gives for the layer's queues ([`Datagrams`],
//! [`DatagramsOwned`]), the writer that
//! sends ([`DatagramWriter`]) and what it sends through ([`DatagramSend`]).
//!
//! Every implementation of the queues gives the same capability, so that
//! the application's code does not change with the implementation; an
//! implementation may add traits of its own. The place of the datagram
//! intent in the composition's sum of intents is the capability's
//! parameter `I`, inferred where it is called; the writer keeps the
//! publishing handle for that place in its share, so that it need not be
//! named.
//!
//! A writer carries the send parameters and destination its datagrams are
//! sent with: [`NoSendOptions`] as made, a [`SendOptions`] once set
//! ([`DatagramWriter::with_send_options`]), as a stream writer does.

use core::{fmt, future::Future};

use bytes::{Buf, Bytes};
use sakuya_stream::{
    connection::LayerEndedError,
    send_options::{NoSendOptions, SendOptions, destination::AnyActiveLinkPath},
};
use snafu::Snafu;

/// What a datagram may hold at most (`DatagramFrameLimits`), in bytes of
/// payload.
///
/// `everywhere` fits every link path the datagram may go to, `somewhere` at
/// least one. Until the link paths' sizes are taken in, both are the limit
/// the peer's `max_datagram_frame_size` sets, counted with a Length field,
/// and 0 when the peer takes no DATAGRAM frames; a datagram between the
/// path's size and that limit is accepted and waits until a link path can
/// carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramFrameLimits {
    /// What fits every link path.
    pub everywhere: usize,
    /// What fits at least one link path.
    pub somewhere: usize,
}

/// [`DatagramSend::send_with`] did not take the datagram; `C` is this
/// endpoint's reason for closing, which the layer's end carries.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
pub enum SendDatagramError<C> {
    /// The peer did not send a `max_datagram_frame_size` other than 0: no
    /// DATAGRAM frame may be sent to it (RFC 9221 §3).
    #[snafu(display("the peer does not take DATAGRAM frames"))]
    NotSupportedByPeer,
    /// The datagram is larger than the peer's `max_datagram_frame_size`
    /// allows (RFC 9221 §3).
    #[snafu(display("a datagram larger than the {limit} bytes the peer takes"))]
    TooLarge {
        /// The largest payload the peer takes, in bytes.
        limit: usize,
    },
    /// The send queue is full, and it takes no new datagram then
    /// ([`DatagramOverflow::RejectNew`](super::DatagramOverflow::RejectNew)).
    #[snafu(display("the datagram send queue is full"))]
    QueueFull,
    /// The layer ended.
    #[snafu(transparent)]
    LayerEnded {
        /// How it ended.
        source: LayerEndedError<C>,
    },
}

/// What a datagram writer sends through (`DatagramSend`): this side's
/// share of the send queue.
pub trait DatagramSend {
    /// The parameters a datagram is sent with.
    type Parameters;
    /// Where a datagram is sent.
    type Destination;
    /// This endpoint's reason for closing, which the layer's end carries.
    type CloseCause;
    /// What a datagram taken gives back: its ticket.
    type Ticket;

    /// Takes `payload` as one datagram, sent with `parameters` to
    /// `destination`, and gives back its ticket.
    ///
    /// # Errors
    ///
    /// [`SendDatagramError`]; nothing is taken then.
    fn send_with(
        &self,
        payload: Bytes,
        parameters: &Self::Parameters,
        destination: &Self::Destination,
    ) -> Result<Self::Ticket, SendDatagramError<Self::CloseCause>>;

    /// What a datagram may hold at most now.
    fn datagram_limits(&self) -> DatagramFrameLimits;
}

/// A borrowed share sends as the share does.
impl<E: DatagramSend + ?Sized> DatagramSend for &E {
    type Parameters = E::Parameters;
    type Destination = E::Destination;
    type CloseCause = E::CloseCause;
    type Ticket = E::Ticket;

    fn send_with(
        &self,
        payload: Bytes,
        parameters: &E::Parameters,
        destination: &E::Destination,
    ) -> Result<E::Ticket, SendDatagramError<E::CloseCause>> {
        (**self).send_with(payload, parameters, destination)
    }

    fn datagram_limits(&self) -> DatagramFrameLimits {
        (**self).datagram_limits()
    }
}

/// A datagram writer (`DatagramWriter`): what the application sends
/// datagrams with.
///
/// `E` is this side's share of the send queue, or a borrow of one
/// ([`borrow_with_send_options`](Self::borrow_with_send_options)); `O` the
/// send parameters and destination its datagrams are sent with,
/// [`NoSendOptions`] until set. A clone sends to the same queue, with the
/// same options.
#[derive(Clone)]
pub struct DatagramWriter<E, O> {
    share: E,
    options: O,
}

impl<E> DatagramWriter<E, NoSendOptions> {
    /// The writer of the share `share`, with no send options.
    pub(crate) fn new(share: E) -> Self {
        Self {
            share,
            options: NoSendOptions,
        }
    }
}

impl<E: DatagramSend, O> DatagramWriter<E, O> {
    /// This writer with `parameters` and `destination` for its datagrams
    /// from now on.
    pub fn with_send_options(
        self,
        parameters: E::Parameters,
        destination: E::Destination,
    ) -> DatagramWriter<E, SendOptions<E::Parameters, E::Destination>> {
        DatagramWriter {
            share: self.share,
            options: SendOptions::new(parameters, destination),
        }
    }

    /// A writer of the same share with `parameters` and `destination`, for
    /// some datagrams; this one keeps its own afterwards.
    pub fn borrow_with_send_options(
        &self,
        parameters: E::Parameters,
        destination: E::Destination,
    ) -> DatagramWriter<&E, SendOptions<E::Parameters, E::Destination>> {
        DatagramWriter {
            share: &self.share,
            options: SendOptions::new(parameters, destination),
        }
    }

    /// What a datagram may hold at most now.
    pub fn datagram_limits(&self) -> DatagramFrameLimits {
        self.share.datagram_limits()
    }
}

impl<E, P, D> DatagramWriter<E, SendOptions<P, D>> {
    /// The send parameters and destination of the datagrams from now on;
    /// those sent keep the ones they were sent with.
    pub fn send_options_mut(&mut self) -> &mut SendOptions<P, D> {
        &mut self.options
    }
}

impl<E, P, D> DatagramWriter<E, SendOptions<P, D>>
where
    E: DatagramSend<Parameters = P, Destination = D>,
{
    /// Send `payload` as one datagram, with the writer's options.
    ///
    /// # Errors
    ///
    /// As [`DatagramSend::send_with`].
    pub fn send(&self, payload: Bytes) -> Result<E::Ticket, SendDatagramError<E::CloseCause>> {
        self.share.send_with(
            payload,
            self.options.parameters(),
            self.options.destination(),
        )
    }
}

impl<E> DatagramWriter<E, NoSendOptions>
where
    E: DatagramSend<Parameters: Default, Destination: From<AnyActiveLinkPath>>,
{
    /// Send `payload` as one datagram, with the default parameters, to any
    /// active link path.
    ///
    /// # Errors
    ///
    /// As [`DatagramSend::send_with`].
    pub fn send(&self, payload: Bytes) -> Result<E::Ticket, SendDatagramError<E::CloseCause>> {
        self.share.send_with(
            payload,
            &E::Parameters::default(),
            &AnyActiveLinkPath.into(),
        )
    }
}

impl<E, O: fmt::Debug> fmt::Debug for DatagramWriter<E, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramWriter")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

// ---- the capability ----

/// Sending and receiving datagrams on a layer (`Datagrams`): what the
/// DATAGRAM extension gives the handle of an established layer, for the
/// layer's queues.
///
/// `I` is where the components the capability is lent are in the
/// connection's nodes and where the datagram intents are in the
/// composition's sum of intents; the compiler infers it. The future of
/// [`recv_datagram`](Self::recv_datagram) borrows the handle: several tasks
/// may receive on the same handle at once; [`DatagramsOwned`] gives one
/// that holds a clone of it instead.
pub trait Datagrams<I> {
    /// What the application reads of one datagram received.
    type Received: Buf;
    /// This side's share of the send queue, which a writer holds.
    type SendShare: DatagramSend;
    /// This endpoint's reason for closing, which the layer's end carries.
    type CloseCause;

    /// A writer that sends on the layer, with no send options.
    fn datagram_writer(&self) -> DatagramWriter<Self::SendShare, NoSendOptions>;

    /// The next datagram received, in the order they arrived.
    ///
    /// # Errors
    ///
    /// [`LayerEndedError`] once the layer ended and every datagram it
    /// received was read.
    fn recv_datagram(
        &self,
    ) -> impl Future<Output = Result<Self::Received, LayerEndedError<Self::CloseCause>>>;
}

/// Receiving datagrams with a future that does not borrow the handle
/// (`DatagramsOwned`): it holds a clone of it, and may go to another task.
/// Every handle that has datagrams, can be cloned and is `'static` has it.
pub trait DatagramsOwned<I>: Datagrams<I> {
    /// As [`Datagrams::recv_datagram`], with a future of its own.
    fn recv_datagram_owned(
        &self,
    ) -> impl Future<Output = Result<Self::Received, LayerEndedError<Self::CloseCause>>> + 'static;
}

/// A clone of the handle goes into the future.
impl<H, I> DatagramsOwned<I> for H
where
    H: Datagrams<I> + Clone + 'static,
    I: 'static,
{
    fn recv_datagram_owned(
        &self,
    ) -> impl Future<Output = Result<Self::Received, LayerEndedError<Self::CloseCause>>> + 'static
    {
        let handle = self.clone();
        async move { handle.recv_datagram().await }
    }
}
