//! The handle of an established layer ([`EstablishedLayerHandle`]) and
//! what it can do with the streams of its layer ([`OpenStreams`],
//! [`AcceptStreams`]).
//!
//! A handle is tied to one established layer: it ends with that layer, and
//! so do the streams opened or accepted through it. It keeps what it reads
//! of the layer, its application protocol and on a server the selected
//! target, also after the layer ended. It holds each part's share of it
//! ([`HandleShare`](super::HandleShare)). Opening and accepting are
//! capabilities version 1 gives the handle, a trait each, implemented by
//! the stream set the composition chooses, on the handle whose shares hold
//! the set's handle; the trait's parameter is the place of that share among
//! the shares and the place of the stream intent in the composition's sum
//! of intents, inferred where it is called. Their futures borrow the
//! handle; the futures of [`OpenStreamsOwned`] and [`AcceptStreamsOwned`]
//! hold a clone of it instead.

use core::{
    fmt,
    future::{Future, poll_fn},
    task::{Context, Poll, Waker},
};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use nitori_tls::{extension::alpn::ProtocolName, role, server::targets::SelectedTarget};
use sakuya_stream::{
    connection::LayerEnd, connection::LayerEndedError, send_options::NoSendOptions,
};
use snafu::Snafu;

use super::{
    connection::{keep_waker, lock, wake_all},
    stream::{StreamReader, StreamWriter},
};

/// The handle of an established layer in the application's hands
/// (`EstablishedLayerHandle`).
///
/// `Sh` is each part's share of the handle, in the order of the list of
/// parts ([`HandleSharesOf`](super::HandleSharesOf) for the level
/// [`handle::EstablishedLayer`](super::handle::EstablishedLayer)): version
/// 1's is the stream set's handle. `N` is the send strategy's intake the
/// streams and the other parts publish their intents through, `A` what the
/// layer runs with of the handshake's selection: the application protocol,
/// on a server together with the selected target. `C` is this endpoint's
/// reason for closing, which the layer's end carries. A clone is the same
/// handle.
pub struct EstablishedLayerHandle<Sh, N, A, C> {
    pub(crate) shares: Sh,
    pub(crate) intake: N,
    pub(crate) layer: Arc<LayerShare<A, C>>,
}

/// What the handles of one layer share: its selection, and its end with
/// the wakers of those who wait for it.
pub(crate) struct LayerShare<A, C> {
    selection: A,
    end: Mutex<LayerEndState<C>>,
}

struct LayerEndState<C> {
    end: Option<LayerEnd<C>>,
    wakers: Vec<Waker>,
}

impl<A, C> LayerShare<A, C> {
    /// The layer ended as `end`; only the first end is kept.
    pub(crate) fn end(&self, end: LayerEnd<C>) {
        let mut state = lock(&self.end);
        if state.end.is_none() {
            state.end = Some(end);
            wake_all(&mut state.wakers);
        }
    }

    pub(crate) fn poll_ended(&self, cx: &mut Context<'_>) -> Poll<LayerEnd<C>> {
        let mut state = lock(&self.end);
        match &state.end {
            Some(end) => Poll::Ready(end.clone()),
            None => {
                keep_waker(&mut state.wakers, cx.waker());
                Poll::Pending
            }
        }
    }
}

impl<Sh, N, A, C> EstablishedLayerHandle<Sh, N, A, C> {
    /// The handle of a layer just built, with each part's share `shares`.
    pub(crate) fn new(shares: Sh, intake: N, selection: A) -> Self {
        Self {
            shares,
            intake,
            layer: Arc::new(LayerShare {
                selection,
                end: Mutex::new(LayerEndState {
                    end: None,
                    wakers: Vec::new(),
                }),
            }),
        }
    }

    /// How the layer ended, once it did; called again, the same end at
    /// once.
    pub fn ended(&self) -> impl Future<Output = LayerEnd<C>> + '_ {
        poll_fn(|cx| self.layer.poll_ended(cx))
    }
}

/// A client's layer runs with the application protocol its handshake
/// selected.
impl<Sh, N, C> EstablishedLayerHandle<Sh, N, Option<ProtocolName<Bytes>>, C> {
    /// The application protocol the layer uses, also after it ended.
    pub fn application_protocol(&self) -> Option<&ProtocolName<Bytes>> {
        self.layer.selection.as_ref()
    }
}

/// A server's layer runs with the target and application protocol its
/// handshake selected, from its ServerHello on.
impl<Sh, N, T, C> EstablishedLayerHandle<Sh, N, SelectedTarget<T>, C> {
    /// The application protocol the layer uses, also after it ended.
    pub fn application_protocol(&self) -> Option<&ProtocolName<Bytes>> {
        self.layer.selection.application_protocol.as_ref()
    }

    /// The target the layer serves and its application protocol, also
    /// after it ended.
    pub fn selected(&self) -> &SelectedTarget<T> {
        &self.layer.selection
    }
}

/// A clone is the same handle.
impl<Sh: Clone, N: Clone, A, C> Clone for EstablishedLayerHandle<Sh, N, A, C> {
    fn clone(&self) -> Self {
        Self {
            shares: self.shares.clone(),
            intake: self.intake.clone(),
            layer: Arc::clone(&self.layer),
        }
    }
}

impl<Sh, N, A, C> fmt::Debug for EstablishedLayerHandle<Sh, N, A, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedLayerHandle")
            .finish_non_exhaustive()
    }
}

/// What a layer runs with of the handshake's selection (`LayerSelection`),
/// and so which side the layer is of: `Role` is
/// [`role::Client`] or [`role::Server`]. The handle's capabilities give
/// what they make the side, as a stream reader that tells a server
/// whether the stream had data in 0-RTT packets.
pub trait LayerSelection {
    /// The side's role.
    type Role: role::HandshakeRole;
}

/// A client's layer runs with the application protocol alone.
impl LayerSelection for Option<ProtocolName<Bytes>> {
    type Role = role::Client;
}

/// A server's layer runs with the selected target.
impl<T> LayerSelection for SelectedTarget<T> {
    type Role = role::Server;
}

// ---- the capabilities of streams ----

/// Opening this side's streams on a layer (`OpenStreams`): what version 1
/// gives the handle of an established layer.
///
/// `I` is where the stream set's handle is among the handle's shares and
/// where the stream intents are in the composition's sum of intents, as a
/// pair; the compiler infers it. The futures borrow the handle: several tasks may
/// open streams on the same handle at once. A stream comes with
/// [`NoSendOptions`]: its parameters and destination are set before it is
/// written to, unless they have defaults.
pub trait OpenStreams<I> {
    /// This side's share of a stream's sending part, which its writer holds.
    type SendShare;
    /// This side's share of a stream's receiving part, which its reader
    /// holds.
    type ReceiveShare;
    /// This endpoint's reason for closing, which the layer's end carries.
    type CloseCause;

    /// Opens a bidirectional stream, waiting while the peer's limit on this
    /// side's streams allows none (the peer's MAX_STREAMS raises it).
    ///
    /// # Errors
    ///
    /// [`LayerEndedError`] once the layer ended.
    #[allow(clippy::type_complexity)]
    fn open_bi(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<Self::CloseCause>,
        >,
    >;

    /// Opens a unidirectional stream, waiting as
    /// [`open_bi`](Self::open_bi) does.
    ///
    /// # Errors
    ///
    /// [`LayerEndedError`] once the layer ended.
    fn open_uni(
        &self,
    ) -> impl Future<
        Output = Result<
            StreamWriter<Self::SendShare, NoSendOptions>,
            LayerEndedError<Self::CloseCause>,
        >,
    >;

    /// Opens a bidirectional stream at once, or fails when the peer's limit
    /// allows none; the peer is then told this side is blocked
    /// (STREAMS_BLOCKED, RFC 9000 §4.6).
    ///
    /// # Errors
    ///
    /// [`TryOpenStreamError::AtLimit`] at the limit,
    /// [`TryOpenStreamError::LayerEnded`] once the layer ended.
    #[allow(clippy::type_complexity)]
    fn try_open_bi(
        &self,
    ) -> Result<
        (
            StreamWriter<Self::SendShare, NoSendOptions>,
            StreamReader<Self::ReceiveShare>,
        ),
        TryOpenStreamError<Self::CloseCause>,
    >;

    /// Opens a unidirectional stream at once, as
    /// [`try_open_bi`](Self::try_open_bi) does.
    ///
    /// # Errors
    ///
    /// As [`try_open_bi`](Self::try_open_bi).
    fn try_open_uni(
        &self,
    ) -> Result<StreamWriter<Self::SendShare, NoSendOptions>, TryOpenStreamError<Self::CloseCause>>;
}

/// Accepting the streams the peer opens on a layer (`AcceptStreams`): what
/// version 1 gives the handle of an established layer.
///
/// `I` is as for [`OpenStreams`]. Streams are accepted in the order their
/// first frames arrived; several tasks may wait on the same handle.
pub trait AcceptStreams<I> {
    /// This side's share of a stream's sending part, which its writer holds.
    type SendShare;
    /// This side's share of a stream's receiving part, which its reader
    /// holds.
    type ReceiveShare;
    /// This endpoint's reason for closing, which the layer's end carries.
    type CloseCause;

    /// The next bidirectional stream the peer opened.
    ///
    /// # Errors
    ///
    /// [`LayerEndedError`] once the layer ended.
    #[allow(clippy::type_complexity)]
    fn accept_bi(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<Self::CloseCause>,
        >,
    >;

    /// The next unidirectional stream the peer opened.
    ///
    /// # Errors
    ///
    /// [`LayerEndedError`] once the layer ended.
    fn accept_uni(
        &self,
    ) -> impl Future<Output = Result<StreamReader<Self::ReceiveShare>, LayerEndedError<Self::CloseCause>>>;
}

/// [`OpenStreams::try_open_bi`] and [`OpenStreams::try_open_uni`] opened
/// no stream; `C` is this endpoint's reason for closing.
#[derive(Debug, Snafu)]
pub enum TryOpenStreamError<C> {
    /// The peer's limit on this side's streams of the type allows no more.
    #[snafu(display("the peer's limit on streams is reached"))]
    AtLimit,
    /// The layer ended.
    #[snafu(transparent)]
    LayerEnded {
        /// How it ended.
        source: LayerEndedError<C>,
    },
}

/// Opening streams with futures that do not borrow the handle
/// (`OpenStreamsOwned`): they hold a clone of it, and may go to another
/// task. Every handle that opens streams, can be cloned and is `'static`
/// has it.
pub trait OpenStreamsOwned<I>: OpenStreams<I> {
    /// As [`OpenStreams::open_bi`], with a future of its own.
    #[allow(clippy::type_complexity)]
    fn open_bi_owned(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static;

    /// As [`OpenStreams::open_uni`], with a future of its own.
    fn open_uni_owned(
        &self,
    ) -> impl Future<
        Output = Result<
            StreamWriter<Self::SendShare, NoSendOptions>,
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static;
}

/// A clone of the handle goes into the future.
impl<H, I> OpenStreamsOwned<I> for H
where
    H: OpenStreams<I> + Clone + 'static,
    I: 'static,
{
    fn open_bi_owned(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static {
        let handle = self.clone();
        async move { handle.open_bi().await }
    }

    fn open_uni_owned(
        &self,
    ) -> impl Future<
        Output = Result<
            StreamWriter<Self::SendShare, NoSendOptions>,
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static {
        let handle = self.clone();
        async move { handle.open_uni().await }
    }
}

/// Accepting streams with futures that do not borrow the handle
/// (`AcceptStreamsOwned`), as [`OpenStreamsOwned`] opens them.
pub trait AcceptStreamsOwned<I>: AcceptStreams<I> {
    /// As [`AcceptStreams::accept_bi`], with a future of its own.
    #[allow(clippy::type_complexity)]
    fn accept_bi_owned(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static;

    /// As [`AcceptStreams::accept_uni`], with a future of its own.
    fn accept_uni_owned(
        &self,
    ) -> impl Future<
        Output = Result<StreamReader<Self::ReceiveShare>, LayerEndedError<Self::CloseCause>>,
    > + 'static;
}

/// A clone of the handle goes into the future.
impl<H, I> AcceptStreamsOwned<I> for H
where
    H: AcceptStreams<I> + Clone + 'static,
    I: 'static,
{
    fn accept_bi_owned(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static {
        let handle = self.clone();
        async move { handle.accept_bi().await }
    }

    fn accept_uni_owned(
        &self,
    ) -> impl Future<
        Output = Result<StreamReader<Self::ReceiveShare>, LayerEndedError<Self::CloseCause>>,
    > + 'static {
        let handle = self.clone();
        async move { handle.accept_uni().await }
    }
}
