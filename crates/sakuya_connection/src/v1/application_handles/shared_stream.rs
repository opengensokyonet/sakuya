//! The capabilities of a stream's parts through the shared connection
//! ([`SharedStreamSend`], [`SharedStreamReceive`]), and opening and
//! accepting streams with them on the handle of an established layer
//! ([`OpenStreams`], [`AcceptStreams`]).
//!
//! Such a capability holds the connection in its wrapper, the identity of
//! its layer, the stream's ID and the pointer to the credential of what it
//! holds ([`CredentialPointer`]); each operation borrows the connection
//! once, is lent the established layer while it is the capability's own,
//! and finds the part by the stream's ID in the stream set. The set keeps
//! the part for it until the credential comes back, with its last result
//! once the stream was reclaimed: the last holder
//! of it hands it back to the set ([`StreamSet::reclaim_writer`],
//! [`StreamSet::reclaim_reader`]) when it drops its capability, through
//! the connection as well; once the layer ended there is nothing to hand
//! it back to. Opening and accepting are written once, for every stream
//! set; what the capabilities do on a stream is the stream set's, which
//! implements [`StreamWrite`](super::stream::StreamWrite),
//! [`StreamRead`](super::stream::StreamRead) and nitori_io's traits for
//! them.

use core::{
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
};

use sakuya_stream::{connection::LayerEndedError, send_options::NoSendOptions};
use sakuya_wire::{
    parts::Selector,
    v1::stream_id::{Directionality, StreamId},
};

use super::{
    connection::{ConnectionHandleRemainsOf, ConnectionHandleStateOf, LayerId},
    credential::{CredentialPointer, HandleCredential},
    established_layer::{
        AcceptStreams, EstablishedLayerHandle, LayerSelection, OpenStreams, TryOpenStreamError,
        lend_layer,
    },
    stream::{StreamReader, StreamWriter},
};
use frunk_core::{HList, hlist_pat};

use crate::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::{GetAt, Take, TakeEach},
    v1::{
        Choices, CloseCauseOf, SendParametersOf, StreamSetFamilyOf,
        send::SendTypes,
        send_planning::{
            ComponentPublishing, PublisherOf, SendStrategyPublisher, StrategyPublisherFor,
        },
        streams::{
            StreamSet, StreamsOf,
            resets::{StreamResetsOf, StreamResetsOfParts},
            send::StreamIntent,
        },
    },
};

/// What hands a credential back to the stream set: the connection, the
/// layer and the stream it is of.
type Reclaim<S> = fn(&S, LayerId, StreamId, HandleCredential);

/// The capability of a stream's sending part through the shared
/// connection (`SharedStreamSend`), which a [`StreamWriter`] holds.
///
/// `T` is the composition's choices, `L` its list of parts, `S` the
/// connection in the wrapper the host chose, `I` where the components it
/// is lent are in the connection's nodes and the place of the stream
/// intents in the composition's sum of intents, and `C` the pointer to the
/// writer's credential. It can be cloned where `C` can: opened or accepted
/// with the credential itself, it is turned into one with a shared
/// credential by [`into_shared`](Self::into_shared). Once the last holder
/// of the credential drops its capability, the writer gives the stream up.
pub struct SharedStreamSend<T, L, S, I, C: CredentialPointer> {
    pub(crate) connection: S,
    pub(crate) layer: LayerId,
    pub(crate) id: StreamId,
    /// `None` only once it was handed back or moved on.
    credential: Option<C>,
    reclaim: Reclaim<S>,
    #[allow(clippy::type_complexity)] // a marker of three type parameters
    places: PhantomData<fn() -> (T, L, I)>,
}

/// The capability of a stream's receiving part through the shared
/// connection (`SharedStreamReceive`), which a [`StreamReader`] holds, as
/// [`SharedStreamSend`] is of a sending part.
///
/// `Ro` is the role of this side, [`role::Client`] or [`role::Server`]: a
/// server's reader also tells whether the stream had data in 0-RTT
/// packets.
///
/// [`role::Client`]: nitori_tls::role::Client
/// [`role::Server`]: nitori_tls::role::Server
pub struct SharedStreamReceive<T, L, S, I, C: CredentialPointer, Ro> {
    pub(crate) connection: S,
    pub(crate) layer: LayerId,
    pub(crate) id: StreamId,
    credential: Option<C>,
    reclaim: Reclaim<S>,
    /// Whether the stream had data in 0-RTT packets, as this capability
    /// last read it from the part.
    pub(crate) zero_rtt: AtomicBool,
    #[allow(clippy::type_complexity)] // a marker of four type parameters
    places: PhantomData<fn() -> (T, L, I, Ro)>,
}

impl<T, L, S, I, C: CredentialPointer> SharedStreamSend<T, L, S, I, C> {
    /// The capability of the sending part of `id` on the layer `layer` of
    /// `connection`, with `credential`, handed back through `reclaim`.
    fn new(
        connection: S,
        layer: LayerId,
        id: StreamId,
        credential: C,
        reclaim: Reclaim<S>,
    ) -> Self {
        Self {
            connection,
            layer,
            id,
            credential: Some(credential),
            reclaim,
            places: PhantomData,
        }
    }
}

impl<T, L, S, I, C: CredentialPointer, Ro> SharedStreamReceive<T, L, S, I, C, Ro> {
    /// The capability of the receiving part of `id`, as
    /// [`SharedStreamSend::new`].
    fn new(
        connection: S,
        layer: LayerId,
        id: StreamId,
        credential: C,
        reclaim: Reclaim<S>,
    ) -> Self {
        Self {
            connection,
            layer,
            id,
            credential: Some(credential),
            reclaim,
            zero_rtt: AtomicBool::new(false),
            places: PhantomData,
        }
    }
}

impl<T, L, S: Clone, I> SharedStreamSend<T, L, S, I, HandleCredential> {
    /// The same capability with the credential behind the shared pointer
    /// `Q` ([`Arc`](alloc::sync::Arc) or [`Rc`](alloc::rc::Rc)), so that it
    /// can be cloned.
    pub fn into_shared<Q>(mut self) -> SharedStreamSend<T, L, S, I, Q>
    where
        Q: CredentialPointer + From<HandleCredential>,
    {
        SharedStreamSend {
            connection: self.connection.clone(),
            layer: self.layer,
            id: self.id,
            credential: self.credential.take().map(Q::from),
            reclaim: self.reclaim,
            places: PhantomData,
        }
    }
}

impl<T, L, S: Clone, I, Ro> SharedStreamReceive<T, L, S, I, HandleCredential, Ro> {
    /// The same capability with the credential behind the shared pointer
    /// `Q` ([`Arc`](alloc::sync::Arc) or [`Rc`](alloc::rc::Rc)), so that it
    /// can be cloned.
    pub fn into_shared<Q>(mut self) -> SharedStreamReceive<T, L, S, I, Q, Ro>
    where
        Q: CredentialPointer + From<HandleCredential>,
    {
        SharedStreamReceive {
            connection: self.connection.clone(),
            layer: self.layer,
            id: self.id,
            credential: self.credential.take().map(Q::from),
            reclaim: self.reclaim,
            zero_rtt: AtomicBool::new(self.zero_rtt.load(Ordering::Relaxed)),
            places: PhantomData,
        }
    }
}

impl<T, L, S: Clone, I, C: CredentialPointer + Clone> Clone for SharedStreamSend<T, L, S, I, C> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            layer: self.layer,
            id: self.id,
            credential: self.credential.clone(),
            reclaim: self.reclaim,
            places: PhantomData,
        }
    }
}

impl<T, L, S: Clone, I, C: CredentialPointer + Clone, Ro> Clone
    for SharedStreamReceive<T, L, S, I, C, Ro>
{
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            layer: self.layer,
            id: self.id,
            credential: self.credential.clone(),
            reclaim: self.reclaim,
            zero_rtt: AtomicBool::new(self.zero_rtt.load(Ordering::Relaxed)),
            places: PhantomData,
        }
    }
}

/// Nothing of it is pinned.
impl<T, L, S, I, C: CredentialPointer> Unpin for SharedStreamSend<T, L, S, I, C> {}

/// Nothing of it is pinned.
impl<T, L, S, I, C: CredentialPointer, Ro> Unpin for SharedStreamReceive<T, L, S, I, C, Ro> {}

/// The last holder of the credential hands it back, and the writer gives
/// the stream up; once the layer ended, nothing is done.
impl<T, L, S, I, C: CredentialPointer> Drop for SharedStreamSend<T, L, S, I, C> {
    fn drop(&mut self) {
        if let Some(credential) = self.credential.take().and_then(C::into_credential) {
            (self.reclaim)(&self.connection, self.layer, self.id, credential);
        }
    }
}

/// The last holder of the credential hands it back, and the reader gives
/// the reading up; once the layer ended, nothing is done.
impl<T, L, S, I, C: CredentialPointer, Ro> Drop for SharedStreamReceive<T, L, S, I, C, Ro> {
    fn drop(&mut self) {
        if let Some(credential) = self.credential.take().and_then(C::into_credential) {
            (self.reclaim)(&self.connection, self.layer, self.id, credential);
        }
    }
}

impl<T, L, S, I, C: CredentialPointer> fmt::Debug for SharedStreamSend<T, L, S, I, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedStreamSend")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<T, L, S, I, C: CredentialPointer, Ro> fmt::Debug for SharedStreamReceive<T, L, S, I, C, Ro> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedStreamReceive")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A writer through the shared connection turns into one with a shared
/// credential, which can be cloned.
impl<T, L, S: Clone, I, O> StreamWriter<SharedStreamSend<T, L, S, I, HandleCredential>, O> {
    /// The same writer with the credential behind the shared pointer `Q`
    /// ([`SharedStreamSend::into_shared`]).
    pub fn into_shared<Q>(self) -> StreamWriter<SharedStreamSend<T, L, S, I, Q>, O>
    where
        Q: CredentialPointer + From<HandleCredential>,
    {
        self.map_share(SharedStreamSend::into_shared)
    }
}

/// A reader through the shared connection turns into one with a shared
/// credential, which can be cloned.
impl<T, L, S: Clone, I, Ro> StreamReader<SharedStreamReceive<T, L, S, I, HandleCredential, Ro>> {
    /// The same reader with the credential behind the shared pointer `Q`
    /// ([`SharedStreamReceive::into_shared`]).
    pub fn into_shared<Q>(self) -> StreamReader<SharedStreamReceive<T, L, S, I, Q, Ro>>
    where
        Q: CredentialPointer + From<HandleCredential>,
    {
        StreamReader::new(self.share.into_shared())
    }
}

// ---- opening, accepting, and handing the credentials back ----

/// What a lend of the layer takes to open, accept and hand back: the stream
/// set, and the send strategy's publisher it is lent.
type HeldSetTakes<T, L> = HList![StreamsOf<T, L>, SendStrategyPublisher<PublisherOf<T, L>>];

/// The sending capability the handle of an established layer opens and
/// accepts, at the places `I`.
type SendOf<T, L, S, I> = SharedStreamSend<T, L, S, I, HandleCredential>;

/// The receiving capability, as [`SendOf`], on the side of the layer's
/// selection `A`.
type ReceiveOf<T, L, S, I, A> =
    SharedStreamReceive<T, L, S, I, HandleCredential, <A as LayerSelection>::Role>;

/// The places of the components and of the stream intents, as the
/// capabilities name them.
type Places<Ie, Ic, Ir, Is, In, I> = (Ie, Ic, Ir, Is, In, I);

/// Opening, accepting and handing back, written once for every stream set.
///
/// `Ie`, `Ic` and `Ir` are where the connection handle's state is in the
/// layer's lineage and in the connection node's, and where version 1's part
/// is in what the parts keep after the end; `Is` and `In` where the stream
/// set and the send strategy's publisher are in the layer's lineage, `I`
/// the place of the stream intents in the composition's sum of intents.
impl<T, L, S, A> EstablishedLayerHandle<T, L, S, A> {
    /// Lend the layer once to `op`, with the stream set and the send
    /// strategy's publisher it is lent; what the set did there is handed on
    /// at the connection afterwards. Otherwise how the layer ended.
    fn with_held_set<R, Ie, Ic, Ir, Is, In, I>(
        connection: &S,
        layer: LayerId,
        op: impl FnOnce(&mut StreamsOf<T, L>, &mut PublisherOf<T, L>) -> R,
    ) -> Result<R, LayerEndedError<CloseCauseOf<T, L>>>
    where
        T: Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>:
            ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
        StreamsOf<T, L>: StreamSet<
                CloseCauseOf<T, L>,
                SendTypes<T, L>,
                StreamResetsOfParts<L>,
                SendParameters = SendParametersOf<T>,
            >,
        PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>
            + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        lend_layer::<T, L, S, _, Ie, Ic, Ir>(connection, layer, |lineage, _| {
            let (hlist_pat![mut set, mut publisher], mut rest) =
                Take::<HeldSetTakes<T, L>, HList![Is, In]>::take(lineage);
            let result = op(&mut set, publisher.publisher_mut());
            if let Some(changed) = publisher.take_changed() {
                rest.publish(changed);
            }
            result
        })
        .map_err(LayerEndedError::new)
    }

    /// Hand the writer's credential of `id` back to the stream set.
    fn reclaim_writer<Ie, Ic, Ir, Is, In, I>(
        connection: &S,
        layer: LayerId,
        id: StreamId,
        credential: HandleCredential,
    ) where
        T: Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>:
            ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
        StreamsOf<T, L>: StreamSet<
                CloseCauseOf<T, L>,
                SendTypes<T, L>,
                StreamResetsOfParts<L>,
                SendParameters = SendParametersOf<T>,
            >,
        PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>
            + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        let _ =
            Self::with_held_set::<_, Ie, Ic, Ir, Is, In, I>(connection, layer, |set, publish| {
                set.reclaim_writer::<I, _>(publish, id, credential);
            });
    }

    /// Hand the reader's credential of `id` back to the stream set.
    fn reclaim_reader<Ie, Ic, Ir, Is, In, I>(
        connection: &S,
        layer: LayerId,
        id: StreamId,
        credential: HandleCredential,
    ) where
        T: Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>:
            ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
        StreamsOf<T, L>: StreamSet<
                CloseCauseOf<T, L>,
                SendTypes<T, L>,
                StreamResetsOfParts<L>,
                SendParameters = SendParametersOf<T>,
            >,
        PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>
            + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        let _ =
            Self::with_held_set::<_, Ie, Ic, Ir, Is, In, I>(connection, layer, |set, publish| {
                set.reclaim_reader::<I, _>(publish, id, credential);
            });
    }

    /// The writer of `id`.
    #[allow(clippy::type_complexity)] // a writer of five type parameters
    fn held_writer<Ie, Ic, Ir, Is, In, I>(
        &self,
        id: StreamId,
    ) -> StreamWriter<SendOf<T, L, S, Places<Ie, Ic, Ir, Is, In, I>>, NoSendOptions>
    where
        T: Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>:
            ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
        StreamsOf<T, L>: StreamSet<
                CloseCauseOf<T, L>,
                SendTypes<T, L>,
                StreamResetsOfParts<L>,
                SendParameters = SendParametersOf<T>,
            >,
        PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>
            + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        let (connection, layer) = self.reach();
        StreamWriter::new(SharedStreamSend::new(
            connection.clone(),
            layer,
            id,
            HandleCredential::new(),
            Self::reclaim_writer::<Ie, Ic, Ir, Is, In, I>,
        ))
    }

    /// The reader of `id`.
    #[allow(clippy::type_complexity)] // a reader of six type parameters
    fn held_reader<Ie, Ic, Ir, Is, In, I>(
        &self,
        id: StreamId,
    ) -> StreamReader<ReceiveOf<T, L, S, Places<Ie, Ic, Ir, Is, In, I>, A>>
    where
        T: Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>:
            ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
        StreamsOf<T, L>: StreamSet<
                CloseCauseOf<T, L>,
                SendTypes<T, L>,
                StreamResetsOfParts<L>,
                SendParameters = SendParametersOf<T>,
            >,
        PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>
            + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
        A: LayerSelection,
    {
        let (connection, layer) = self.reach();
        StreamReader::new(SharedStreamReceive::new(
            connection.clone(),
            layer,
            id,
            HandleCredential::new(),
            Self::reclaim_reader::<Ie, Ic, Ir, Is, In, I>,
        ))
    }

    /// Open a stream of `directionality` now; at the limit, keep `waker` if
    /// one is given.
    fn open_held_now<Ie, Ic, Ir, Is, In, I>(
        &self,
        directionality: Directionality,
        waker: Option<&core::task::Waker>,
    ) -> Result<StreamId, TryOpenStreamError<CloseCauseOf<T, L>>>
    where
        T: Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>:
            ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
        StreamsOf<T, L>: StreamSet<
                CloseCauseOf<T, L>,
                SendTypes<T, L>,
                StreamResetsOfParts<L>,
                SendParameters = SendParametersOf<T>,
            >,
        PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>
            + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        let (connection, layer) = self.reach();
        Self::with_held_set::<_, Ie, Ic, Ir, Is, In, I>(connection, layer, |set, publish| {
            set.open_held::<I, _>(publish, directionality, waker)
        })
        .unwrap_or_else(|ended| Err(ended.into()))
    }

    /// The next stream of `directionality` the peer opened, or `Pending`
    /// with the waker of `cx` kept.
    fn poll_accept_held_now<Ie, Ic, Ir, Is, In, I>(
        &self,
        cx: &mut core::task::Context<'_>,
        directionality: Directionality,
    ) -> Poll<Result<StreamId, LayerEndedError<CloseCauseOf<T, L>>>>
    where
        T: Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>:
            ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
        StreamsOf<T, L>: StreamSet<
                CloseCauseOf<T, L>,
                SendTypes<T, L>,
                StreamResetsOfParts<L>,
                SendParameters = SendParametersOf<T>,
            >,
        PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>
            + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        let (connection, layer) = self.reach();
        Self::with_held_set::<_, Ie, Ic, Ir, Is, In, I>(connection, layer, |set, _| {
            set.poll_accept_held(cx, directionality)
        })
        .unwrap_or_else(|ended| Poll::Ready(Err(ended)))
    }
}

/// What a wait to open gives for one try: at the limit it waits.
fn waited<X, C>(opened: Result<X, TryOpenStreamError<C>>) -> Poll<Result<X, LayerEndedError<C>>> {
    match opened {
        Ok(opened) => Poll::Ready(Ok(opened)),
        Err(TryOpenStreamError::AtLimit) => Poll::Pending,
        Err(TryOpenStreamError::LayerEnded { source }) => Poll::Ready(Err(source)),
    }
}

/// The handle of an established layer opens this side's streams through
/// the shared connection, whatever its stream set: each try, and each poll
/// of a wait, lends the layer once and has the set open a stream whose
/// parts it keeps for their holders, lent the send strategy's publisher, with
/// `I` the place of the stream intents. What it opens holds the connection, the layer's
/// identity, the stream's ID and the credential itself.
impl<T, L, S, A, Ie, Ic, Ir, Is, In, I> OpenStreams<(Ie, Ic, Ir, Is, In, I)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            SendParameters = SendParametersOf<T>,
        >,
    PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    A: LayerSelection,
{
    type SendCapability = SendOf<T, L, S, Places<Ie, Ic, Ir, Is, In, I>>;
    type ReceiveCapability = ReceiveOf<T, L, S, Places<Ie, Ic, Ir, Is, In, I>, A>;
    type CloseCause = CloseCauseOf<T, L>;

    fn open_bi(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendCapability, NoSendOptions>,
                StreamReader<Self::ReceiveCapability>,
            ),
            LayerEndedError<CloseCauseOf<T, L>>,
        >,
    > {
        poll_fn(move |cx| {
            waited(self.open_held_now::<Ie, Ic, Ir, Is, In, I>(
                Directionality::Bidirectional,
                Some(cx.waker()),
            ))
            .map_ok(|id| (self.held_writer(id), self.held_reader(id)))
        })
    }

    fn open_uni(
        &self,
    ) -> impl Future<
        Output = Result<
            StreamWriter<Self::SendCapability, NoSendOptions>,
            LayerEndedError<CloseCauseOf<T, L>>,
        >,
    > {
        poll_fn(move |cx| {
            waited(self.open_held_now::<Ie, Ic, Ir, Is, In, I>(
                Directionality::Unidirectional,
                Some(cx.waker()),
            ))
            .map_ok(|id| self.held_writer(id))
        })
    }

    fn try_open_bi(
        &self,
    ) -> Result<
        (
            StreamWriter<Self::SendCapability, NoSendOptions>,
            StreamReader<Self::ReceiveCapability>,
        ),
        TryOpenStreamError<CloseCauseOf<T, L>>,
    > {
        self.open_held_now::<Ie, Ic, Ir, Is, In, I>(Directionality::Bidirectional, None)
            .map(|id| (self.held_writer(id), self.held_reader(id)))
    }

    fn try_open_uni(
        &self,
    ) -> Result<
        StreamWriter<Self::SendCapability, NoSendOptions>,
        TryOpenStreamError<CloseCauseOf<T, L>>,
    > {
        self.open_held_now::<Ie, Ic, Ir, Is, In, I>(Directionality::Unidirectional, None)
            .map(|id| self.held_writer(id))
    }
}

/// The handle of an established layer accepts the peer's streams through
/// the shared connection, whatever its stream set, in the order their
/// first frames arrived; each poll lends the layer once, and the places
/// are as for opening.
impl<T, L, S, A, Ie, Ic, Ir, Is, In, I> AcceptStreams<(Ie, Ic, Ir, Is, In, I)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            SendParameters = SendParametersOf<T>,
        >,
    PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, I>,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, HeldSetTakes<T, L>, HList![Is, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    A: LayerSelection,
{
    type SendCapability = SendOf<T, L, S, Places<Ie, Ic, Ir, Is, In, I>>;
    type ReceiveCapability = ReceiveOf<T, L, S, Places<Ie, Ic, Ir, Is, In, I>, A>;
    type CloseCause = CloseCauseOf<T, L>;

    fn accept_bi(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendCapability, NoSendOptions>,
                StreamReader<Self::ReceiveCapability>,
            ),
            LayerEndedError<CloseCauseOf<T, L>>,
        >,
    > {
        poll_fn(move |cx| {
            self.poll_accept_held_now::<Ie, Ic, Ir, Is, In, I>(cx, Directionality::Bidirectional)
                .map_ok(|id| (self.held_writer(id), self.held_reader(id)))
        })
    }

    fn accept_uni(
        &self,
    ) -> impl Future<
        Output = Result<StreamReader<Self::ReceiveCapability>, LayerEndedError<CloseCauseOf<T, L>>>,
    > {
        poll_fn(move |cx| {
            self.poll_accept_held_now::<Ie, Ic, Ir, Is, In, I>(cx, Directionality::Unidirectional)
                .map_ok(|id| self.held_reader(id))
        })
    }
}
