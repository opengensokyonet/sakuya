//! The handle of an established layer ([`EstablishedLayerHandle`]) and
//! what it can do with the streams of its layer: through the shared
//! connection ([`OpenStreams`], [`AcceptStreams`]), and, where the stream
//! set gives them, with independent shares ([`OpenDetachedStreams`],
//! [`AcceptDetachedStreams`]).
//!
//! A handle is tied to one established layer: it ends with that layer, and
//! so do the streams opened or accepted through it. It keeps what it reads
//! of the layer, its application protocol and on a server the selected
//! target, also after the layer ended. It holds the connection in its
//! wrapper and the layer's identity; each operation borrows the connection
//! once and is lent the established layer while it is the handle's own.
//! Opening and accepting are capabilities version 1 gives the handle, a
//! trait each: through the shared connection for every stream set, with
//! independent shares for a stream set that gives them; the trait's
//! parameter is where the components it uses are and the place of the
//! stream intent in the composition's sum of intents, inferred where it is
//! called. Their futures borrow the handle; the futures of the `Owned`
//! traits ([`OpenStreamsOwned`], [`AcceptStreamsOwned`] and their detached
//! forms) hold a clone of it instead.

use crate::v1::common_choices::V1Choices;
use alloc::sync::Arc;
use core::{
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
};

use bytes::Bytes;
use kasen_handshake::{extension::alpn::ProtocolName, role, server::targets::SelectedTarget};
use sakuya_stream_v1::{
    connection::{AbortCause, CloseReason, LayerEnd, LayerEndedError},
    send_options::NoSendOptions,
};
use sakuya_wire::parts::Selector;
use snafu::Snafu;

use super::{
    connection::{ConnectionHandleRemainsOf, ConnectionHandleStateOf, LayerId, poll_kept},
    stream::{StreamReader, StreamWriter},
};
use crate::{
    clock::InstantOf,
    component::LineageOf,
    driver::{LendNode, NotLent},
    error::ConnectionErrorsOf,
    layer,
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::GetAt,
    v1::CloseCauseOf,
};

/// The handle of an established layer in the application's hands
/// (`EstablishedLayerHandle`).
///
/// `T` is the composition's choices, `L` its list of parts, `S` the
/// connection in the wrapper the host chose, `A` what the layer runs with
/// of the handshake's selection: the application protocol, on a server
/// together with the selected target. A clone is the same handle.
pub struct EstablishedLayerHandle<T, L, S, A> {
    layer: SharedEstablishedLayer<S>,
    selection: Arc<A>,
    types: PhantomData<fn() -> (T, L)>,
}

impl<T, L, S, A> EstablishedLayerHandle<T, L, S, A> {
    /// The handle of the layer `id` of `connection`, which runs with
    /// `selection`.
    pub(crate) fn new(connection: S, id: LayerId, selection: Arc<A>) -> Self {
        Self {
            layer: SharedEstablishedLayer { connection, id },
            selection,
            types: PhantomData,
        }
    }
}

/// One established layer of a connection, reached through the shared
/// connection (`SharedEstablishedLayer`): the connection in the wrapper the
/// host chose, and the layer's identity among the layers of that
/// connection.
///
/// The two are made together, as the connection gives the layer's handle,
/// and cannot be taken apart and paired anew, so a lend of the layer names
/// a layer of the connection it borrows. A capability through the shared
/// connection holds one; a clone is the same layer.
#[derive(Clone)]
pub struct SharedEstablishedLayer<S> {
    connection: S,
    id: LayerId,
}

impl<S> SharedEstablishedLayer<S> {
    /// The layer's identity among the layers of its connection.
    pub fn id(&self) -> LayerId {
        self.id
    }
}

/// It shows which layer it is, not the connection.
impl<S> fmt::Debug for SharedEstablishedLayer<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedEstablishedLayer")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<T, L, S, A> EstablishedLayerHandle<T, L, S, A>
where
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
{
    /// How the layer ended, once it did; called again, the same end at
    /// once. `I` is where the connection handle's state is in the
    /// connection node's lineage, `Ir` where version 1's part is in what
    /// the parts keep after the end; the compiler infers them.
    pub fn ended<I, Ir>(&self) -> impl Future<Output = LayerEnd<CloseCauseOf<T, L>>> + '_
    where
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, I>,
    {
        poll_fn(|cx| {
            poll_kept::<T, L, S, _, I, Ir>(&self.layer.connection, cx, |kept, _| {
                kept.layer_end(self.layer.id)
            })
        })
    }

    /// Lend the layer to `op` once, while it is this handle's: the
    /// connection is borrowed for it, and has the layer's node. Otherwise
    /// how the layer ended.
    ///
    /// `Ie` is where the connection handle's state is in the layer's
    /// lineage, `Ic` where it is in the connection node's, `Ir` where
    /// version 1's part is in what the parts keep after the end.
    pub fn lend_layer<R, Ie, Ic, Ir>(
        &self,
        op: impl for<'v> FnOnce(LineageOf<'v, T, L, layer::Established>, InstantOf<T>) -> R,
    ) -> Result<R, LayerEnd<CloseCauseOf<T, L>>>
    where
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        self.layer.lend_layer::<T, L, R, Ie, Ic, Ir>(op)
    }

    /// The layer reached through the shared connection: the connection in
    /// its wrapper and the layer's identity.
    pub fn reach(&self) -> &SharedEstablishedLayer<S> {
        &self.layer
    }
}

/// What a lend of a layer reaches (`LayerReach`): the layer, while it is
/// the connection's, or else how it ended and what keeps its records.
pub enum LayerReach<'a, 'v, T: V1Choices, L: LineagePartList<T> + ConnectionErrorsOf> {
    /// The layer's lineage, and the instant.
    Layer(LineageOf<'v, T, L, layer::Established>, InstantOf<T>),
    /// The layer is gone.
    Gone(LayerGone<'a, 'v, T, L>, LayerEnd<CloseCauseOf<T, L>>),
}

/// What keeps the records of a layer that is gone (`LayerGone`): the
/// connection node, while the connection runs, or what the parts keep
/// after the connection's end.
pub enum LayerGone<'a, 'v, T: V1Choices, L: LineagePartList<T>> {
    /// The connection runs.
    Connection(LineageOf<'v, T, L, layer::Connection>),
    /// The connection ended.
    Ended(&'a mut RemainsOf<T, L>),
}

impl<S> SharedEstablishedLayer<S> {
    /// Lend the layer to `op` once, while it is the connection's: the
    /// connection is borrowed for it, and has the layer's node. Otherwise
    /// how the layer ended. See [`EstablishedLayerHandle::lend_layer`].
    pub fn lend_layer<T, L, R, Ie, Ic, Ir>(
        &self,
        op: impl for<'v> FnOnce(LineageOf<'v, T, L, layer::Established>, InstantOf<T>) -> R,
    ) -> Result<R, LayerEnd<CloseCauseOf<T, L>>>
    where
        T: V1Choices,
        L: LineagePartList<T> + ConnectionErrorsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        self.lend_layer_or::<T, L, _, Ie, Ic, Ir>(|reach| match reach {
            LayerReach::Layer(lineage, now) => Ok(op(lineage, now)),
            LayerReach::Gone(_, end) => Err(end),
        })
        .and_then(|done| done)
    }

    /// Lend what `op` reaches of the layer once: the layer while it is the
    /// connection's, or else how it ended and what keeps its records. The
    /// connection is borrowed once.
    pub fn lend_layer_or<T, L, R, Ie, Ic, Ir>(
        &self,
        op: impl for<'a, 'v> FnOnce(LayerReach<'a, 'v, T, L>) -> R,
    ) -> Result<R, LayerEnd<CloseCauseOf<T, L>>>
    where
        T: V1Choices,
        L: LineagePartList<T> + ConnectionErrorsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        let id = self.id;
        let mut op = Some(op);
        self.connection.with(|driver| {
            let lent = driver.lend::<layer::Established, _>((), |lineage, now| {
                if !lineage
                    .get::<ConnectionHandleStateOf<T, L>, Ie>()
                    .is_current(id)
                {
                    return (None, None);
                }
                let op = op.take().expect("called once");
                (Some(op(LayerReach::Layer(lineage, now))), None)
            });
            let ended = |remains: &mut RemainsOf<T, L>| {
                Selector::<ConnectionHandleRemainsOf<T, L>, Ir>::get_mut(remains)
                    .ended()
                    .layer_end(id)
                    .unwrap_or_else(unknown_end)
            };
            match lent {
                Ok(Some(done)) => return Ok(done),
                // another layer, or none: this one ended
                Ok(None) | Err(NotLent::Absent) => {}
                Err(NotLent::Ended(remains)) => {
                    let end = ended(remains);
                    let op = op.take().expect("called once");
                    return Ok(op(LayerReach::Gone(LayerGone::Ended(remains), end)));
                }
            }
            let lent = driver.lend::<layer::Connection, _>((), |lineage, _| {
                let end = lineage
                    .get::<ConnectionHandleStateOf<T, L>, Ic>()
                    .kept()
                    .layer_end(id)
                    .unwrap_or_else(unknown_end);
                let op = op.take().expect("called once");
                (
                    op(LayerReach::Gone(LayerGone::Connection(lineage), end)),
                    None,
                )
            });
            match lent {
                Ok(done) => Ok(done),
                Err(NotLent::Ended(remains)) => {
                    let end = ended(remains);
                    let op = op.take().expect("called once");
                    Ok(op(LayerReach::Gone(LayerGone::Ended(remains), end)))
                }
                // invariant: the connection node is there from the
                // connection's making on, and a layer's handle comes after
                Err(NotLent::Absent) => Err(unknown_end()),
            }
        })
    }
}

/// The end of a layer whose end is not kept.
pub(crate) fn unknown_end<C>() -> LayerEnd<C> {
    // invariant: a layer is reached only with the connection that built it
    // (`SharedEstablishedLayer` pairs the two as the handle is given), and a
    // layer that is no longer the connection's has its end kept, as has
    // every layer once the connection ended
    debug_assert!(false, "a layer that is gone has no end kept");
    LayerEnd::ConnectionClosed(CloseReason::Aborted(AbortCause::DriverDropped))
}

/// A client's layer runs with the application protocol its handshake
/// selected.
impl<T, L, S> EstablishedLayerHandle<T, L, S, Option<ProtocolName<Bytes>>> {
    /// The application protocol the layer uses, also after it ended.
    pub fn application_protocol(&self) -> Option<&ProtocolName<Bytes>> {
        self.selection.as_ref().as_ref()
    }
}

/// A server's layer runs with the target and application protocol its
/// handshake selected, from its ServerHello on.
impl<T, L, S, X> EstablishedLayerHandle<T, L, S, SelectedTarget<X>> {
    /// The application protocol the layer uses, also after it ended.
    pub fn application_protocol(&self) -> Option<&ProtocolName<Bytes>> {
        self.selection.application_protocol.as_ref()
    }

    /// The target the layer serves and its application protocol, also
    /// after it ended.
    pub fn selected(&self) -> &SelectedTarget<X> {
        &self.selection
    }
}

/// A clone is the same handle.
impl<T, L, S: Clone, A> Clone for EstablishedLayerHandle<T, L, S, A> {
    fn clone(&self) -> Self {
        Self {
            layer: self.layer.clone(),
            selection: Arc::clone(&self.selection),
            types: PhantomData,
        }
    }
}

impl<T, L, S, A> fmt::Debug for EstablishedLayerHandle<T, L, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedLayerHandle")
            .field("id", &self.layer.id)
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

/// Opening this side's streams on a layer through the shared connection
/// (`OpenStreams`): what version 1 gives the handle of an established
/// layer, whatever its stream set. Each part of a stream opened comes with
/// the credential itself, and the set keeps it for its holders until the
/// credential comes back.
///
/// `I` is where the components the capability is lent are in the
/// connection's nodes and where the stream intents are in the
/// composition's sum of intents, as a tuple; the compiler infers it. The
/// futures borrow the handle: several tasks may open streams on the same
/// handle at once. A stream comes with
/// [`NoSendOptions`]: its parameters and destination are set before it is
/// written to, unless they have defaults.
pub trait OpenStreams<I> {
    /// The capability of a stream's sending part through the shared
    /// connection, which its writer holds.
    type SendCapability;
    /// The capability of a stream's receiving part through the shared
    /// connection, which its reader holds.
    type ReceiveCapability;
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
                StreamWriter<Self::SendCapability, NoSendOptions>,
                StreamReader<Self::ReceiveCapability>,
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
            StreamWriter<Self::SendCapability, NoSendOptions>,
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
            StreamWriter<Self::SendCapability, NoSendOptions>,
            StreamReader<Self::ReceiveCapability>,
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
    ) -> Result<
        StreamWriter<Self::SendCapability, NoSendOptions>,
        TryOpenStreamError<Self::CloseCause>,
    >;
}

/// Accepting the streams the peer opens on a layer through the shared
/// connection (`AcceptStreams`), as [`OpenStreams`] opens them.
///
/// `I` is as for [`OpenStreams`]. Streams are accepted in the order their
/// first frames arrived; several tasks may wait on the same handle.
pub trait AcceptStreams<I> {
    /// The capability of a stream's sending part through the shared
    /// connection, which its writer holds.
    type SendCapability;
    /// The capability of a stream's receiving part through the shared
    /// connection, which its reader holds.
    type ReceiveCapability;
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
                StreamWriter<Self::SendCapability, NoSendOptions>,
                StreamReader<Self::ReceiveCapability>,
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
    ) -> impl Future<
        Output = Result<StreamReader<Self::ReceiveCapability>, LayerEndedError<Self::CloseCause>>,
    >;
}

/// [`OpenStreams::try_open_bi`] and [`OpenStreams::try_open_uni`], or
/// their detached forms, opened no stream; `C` is this endpoint's reason
/// for closing.
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
                StreamWriter<Self::SendCapability, NoSendOptions>,
                StreamReader<Self::ReceiveCapability>,
            ),
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static;

    /// As [`OpenStreams::open_uni`], with a future of its own.
    fn open_uni_owned(
        &self,
    ) -> impl Future<
        Output = Result<
            StreamWriter<Self::SendCapability, NoSendOptions>,
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
                StreamWriter<Self::SendCapability, NoSendOptions>,
                StreamReader<Self::ReceiveCapability>,
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
            StreamWriter<Self::SendCapability, NoSendOptions>,
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
                StreamWriter<Self::SendCapability, NoSendOptions>,
                StreamReader<Self::ReceiveCapability>,
            ),
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static;

    /// As [`AcceptStreams::accept_uni`], with a future of its own.
    fn accept_uni_owned(
        &self,
    ) -> impl Future<
        Output = Result<StreamReader<Self::ReceiveCapability>, LayerEndedError<Self::CloseCause>>,
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
                StreamWriter<Self::SendCapability, NoSendOptions>,
                StreamReader<Self::ReceiveCapability>,
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
        Output = Result<StreamReader<Self::ReceiveCapability>, LayerEndedError<Self::CloseCause>>,
    > + 'static {
        let handle = self.clone();
        async move { handle.accept_uni().await }
    }
}

// ---- the capabilities of streams with independent shares ----

/// Opening this side's streams on a layer with independent shares
/// (`OpenDetachedStreams`): what version 1 gives the handle of an
/// established layer whose stream set gives shares that are held apart
/// from the connection, as [`OpenStreams`] opens them through the shared
/// connection.
///
/// `I` is where the components the capability is lent are in the
/// connection's nodes and where the stream intents are in the
/// composition's sum of intents, as a tuple; the compiler infers it. The
/// futures borrow the handle: several tasks may open streams on the same
/// handle at once. A stream comes with
/// [`NoSendOptions`]: its parameters and destination are set before it is
/// written to, unless they have defaults.
pub trait OpenDetachedStreams<I> {
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
    fn open_bi_detached(
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
    /// [`open_bi_detached`](Self::open_bi_detached) does.
    ///
    /// # Errors
    ///
    /// [`LayerEndedError`] once the layer ended.
    fn open_uni_detached(
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
    fn try_open_bi_detached(
        &self,
    ) -> Result<
        (
            StreamWriter<Self::SendShare, NoSendOptions>,
            StreamReader<Self::ReceiveShare>,
        ),
        TryOpenStreamError<Self::CloseCause>,
    >;

    /// Opens a unidirectional stream at once, as
    /// [`try_open_bi_detached`](Self::try_open_bi_detached) does.
    ///
    /// # Errors
    ///
    /// As [`try_open_bi_detached`](Self::try_open_bi_detached).
    fn try_open_uni_detached(
        &self,
    ) -> Result<StreamWriter<Self::SendShare, NoSendOptions>, TryOpenStreamError<Self::CloseCause>>;
}

/// Accepting the streams the peer opens on a layer with independent shares
/// (`AcceptDetachedStreams`), as [`AcceptStreams`] accepts them through the
/// shared connection.
///
/// `I` is as for [`OpenStreams`]. Streams are accepted in the order their
/// first frames arrived; several tasks may wait on the same handle.
pub trait AcceptDetachedStreams<I> {
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
    fn accept_bi_detached(
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
    fn accept_uni_detached(
        &self,
    ) -> impl Future<Output = Result<StreamReader<Self::ReceiveShare>, LayerEndedError<Self::CloseCause>>>;
}

/// Opening streams with independent shares and futures that do not borrow
/// the handle (`OpenDetachedStreamsOwned`), as [`OpenStreamsOwned`] opens
/// them.
pub trait OpenDetachedStreamsOwned<I>: OpenDetachedStreams<I> {
    /// As [`OpenDetachedStreams::open_bi_detached`], with a future of its own.
    #[allow(clippy::type_complexity)]
    fn open_bi_detached_owned(
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

    /// As [`OpenDetachedStreams::open_uni_detached`], with a future of its own.
    fn open_uni_detached_owned(
        &self,
    ) -> impl Future<
        Output = Result<
            StreamWriter<Self::SendShare, NoSendOptions>,
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static;
}

/// A clone of the handle goes into the future.
impl<H, I> OpenDetachedStreamsOwned<I> for H
where
    H: OpenDetachedStreams<I> + Clone + 'static,
    I: 'static,
{
    fn open_bi_detached_owned(
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
        async move { handle.open_bi_detached().await }
    }

    fn open_uni_detached_owned(
        &self,
    ) -> impl Future<
        Output = Result<
            StreamWriter<Self::SendShare, NoSendOptions>,
            LayerEndedError<Self::CloseCause>,
        >,
    > + 'static {
        let handle = self.clone();
        async move { handle.open_uni_detached().await }
    }
}

/// Accepting streams with independent shares and futures that do not
/// borrow the handle (`AcceptDetachedStreamsOwned`), as
/// [`AcceptStreamsOwned`] accepts them.
pub trait AcceptDetachedStreamsOwned<I>: AcceptDetachedStreams<I> {
    /// As [`AcceptDetachedStreams::accept_bi_detached`], with a future of its own.
    #[allow(clippy::type_complexity)]
    fn accept_bi_detached_owned(
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

    /// As [`AcceptDetachedStreams::accept_uni_detached`], with a future of its own.
    fn accept_uni_detached_owned(
        &self,
    ) -> impl Future<
        Output = Result<StreamReader<Self::ReceiveShare>, LayerEndedError<Self::CloseCause>>,
    > + 'static;
}

/// A clone of the handle goes into the future.
impl<H, I> AcceptDetachedStreamsOwned<I> for H
where
    H: AcceptDetachedStreams<I> + Clone + 'static,
    I: 'static,
{
    fn accept_bi_detached_owned(
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
        async move { handle.accept_bi_detached().await }
    }

    fn accept_uni_detached_owned(
        &self,
    ) -> impl Future<
        Output = Result<StreamReader<Self::ReceiveShare>, LayerEndedError<Self::CloseCause>>,
    > + 'static {
        let handle = self.clone();
        async move { handle.accept_uni_detached().await }
    }
}
