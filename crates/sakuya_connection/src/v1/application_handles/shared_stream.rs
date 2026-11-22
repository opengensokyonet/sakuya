//! The capabilities of a stream's parts through the shared connection
//! ([`SharedStreamSend`], [`SharedStreamReceive`]), and opening and
//! accepting streams with them on the handle of an established layer
//! ([`OpenStreams`], [`AcceptStreams`]).
//!
//! Such a capability holds the connection in its wrapper, the identity of
//! its layer and the pointer to the credential of what it holds
//! ([`CredentialPointer`]), which names the stream
//! ([`StreamWriterCredential`], [`StreamReaderCredential`]); each operation
//! borrows the connection once, is lent the established layer while it is
//! the capability's own, and finds the part by the stream's ID in the
//! stream set. The set keeps
//! the part for it until the credential comes back, with its last result
//! once the stream was reclaimed: the last holder
//! of it hands it back to the set ([`StreamSet::reclaim_writer`],
//! [`StreamSet::reclaim_reader`]) when it drops its capability, through
//! the connection as well; once the layer ended there is nothing to hand
//! it back to. Opening, accepting and what the capabilities do on a stream
//! are written once, for every stream set: an operation names the part to
//! the set by lending it the credential, and the set does it ([`StreamSet::poll_write`] and the
//! others), lent the send strategy's publisher.

use crate::v1::common_choices::V1Choices;
use core::{
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};
use sakuya_stream_sets::resets::{StreamResets, StreamResetsOf, StreamResetsOfParts};

use bytes::{Buf, BufMut};
use kasen_handshake::role;
use nitori_io::{Read, ReadChunk};
use sakuya_stream_v1::{
    connection::LayerEndedError,
    receive::{read::ReadError, stop::StopError},
    send::{
        finish::{CloseError, ResetError},
        write::{FlushError, WriteError, WriteReport},
    },
    send_options::{NoSendOptions, destination::AnyActiveLinkPath},
};
use sakuya_wire::parts::Selector;
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode,
    stream_id::{Directionality, StreamId},
};

use super::{
    connection::{ConnectionHandleRemainsOf, ConnectionHandleStateOf},
    credential::CredentialPointer,
    established_layer::{
        AcceptStreams, EstablishedLayerHandle, LayerSelection, OpenStreams, SharedEstablishedLayer,
        TryOpenStreamError,
    },
    stream::{AllAcknowledgedError, StreamRead, StreamReader, StreamWrite, StreamWriter},
};
use frunk_core::{HList, hlist_pat};

use crate::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::{GetAt, Take, TakeEach},
    v1::{
        CloseCauseOf, SendParametersOf, StreamSetFamilyOf,
        send::SendTypes,
        send_planning::{
            ComponentPublishing, HostSendStrategyTypes, PublisherOf, SendStrategyPublisher,
            StrategyPublisherFor,
        },
        streams::{
            StreamReaderCredential, StreamSet, StreamWriterCredential, StreamsOf, held_part_gone,
            send::StreamIntent,
        },
    },
};

/// What hands a credential `Cr` back to the stream set: the layer it is of,
/// with its connection, and the credential, which names the stream.
type Reclaim<S, Cr> = fn(&SharedEstablishedLayer<S>, Cr);

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
pub struct SharedStreamSend<T, L, S, I, C: CredentialPointer<StreamWriterCredential>> {
    layer: SharedEstablishedLayer<S>,
    /// `None` only once it was handed back or moved on.
    credential: Option<C>,
    reclaim: Reclaim<S, StreamWriterCredential>,
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
/// [`role::Client`]: kasen_handshake::role::Client
/// [`role::Server`]: kasen_handshake::role::Server
pub struct SharedStreamReceive<T, L, S, I, C: CredentialPointer<StreamReaderCredential>, Ro> {
    layer: SharedEstablishedLayer<S>,
    credential: Option<C>,
    reclaim: Reclaim<S, StreamReaderCredential>,
    /// Whether the stream had data in 0-RTT packets, as this capability
    /// last read it from the part.
    pub(crate) zero_rtt: AtomicBool,
    #[allow(clippy::type_complexity)] // a marker of four type parameters
    places: PhantomData<fn() -> (T, L, I, Ro)>,
}

impl<T, L, S, I, C: CredentialPointer<StreamWriterCredential>> SharedStreamSend<T, L, S, I, C> {
    /// The capability of the sending part `credential` names, on the
    /// layer `layer`, handed back through `reclaim`.
    fn new(
        layer: SharedEstablishedLayer<S>,
        credential: C,
        reclaim: Reclaim<S, StreamWriterCredential>,
    ) -> Self {
        Self {
            layer,
            credential: Some(credential),
            reclaim,
            places: PhantomData,
        }
    }

    /// The stream's ID, while the capability holds its credential.
    fn stream_id(&self) -> Option<StreamId> {
        Some(self.credential.as_ref()?.credential().stream_id())
    }
}

impl<T, L, S, I, C: CredentialPointer<StreamReaderCredential>, Ro>
    SharedStreamReceive<T, L, S, I, C, Ro>
{
    /// The capability of the receiving part `credential` names, as
    /// [`SharedStreamSend::new`].
    fn new(
        layer: SharedEstablishedLayer<S>,
        credential: C,
        reclaim: Reclaim<S, StreamReaderCredential>,
    ) -> Self {
        Self {
            layer,
            credential: Some(credential),
            reclaim,
            zero_rtt: AtomicBool::new(false),
            places: PhantomData,
        }
    }

    /// The stream's ID, while the capability holds its credential.
    fn stream_id(&self) -> Option<StreamId> {
        Some(self.credential.as_ref()?.credential().stream_id())
    }
}

impl<T, L, S: Clone, I> SharedStreamSend<T, L, S, I, StreamWriterCredential> {
    /// The same capability with the credential behind the shared pointer
    /// `Q` ([`Arc`](alloc::sync::Arc) or [`Rc`](alloc::rc::Rc)), so that it
    /// can be cloned.
    pub fn into_shared<Q>(mut self) -> SharedStreamSend<T, L, S, I, Q>
    where
        Q: CredentialPointer<StreamWriterCredential> + From<StreamWriterCredential>,
    {
        SharedStreamSend {
            layer: self.layer.clone(),
            credential: self.credential.take().map(Q::from),
            reclaim: self.reclaim,
            places: PhantomData,
        }
    }
}

impl<T, L, S: Clone, I, Ro> SharedStreamReceive<T, L, S, I, StreamReaderCredential, Ro> {
    /// The same capability with the credential behind the shared pointer
    /// `Q` ([`Arc`](alloc::sync::Arc) or [`Rc`](alloc::rc::Rc)), so that it
    /// can be cloned.
    pub fn into_shared<Q>(mut self) -> SharedStreamReceive<T, L, S, I, Q, Ro>
    where
        Q: CredentialPointer<StreamReaderCredential> + From<StreamReaderCredential>,
    {
        SharedStreamReceive {
            layer: self.layer.clone(),
            credential: self.credential.take().map(Q::from),
            reclaim: self.reclaim,
            zero_rtt: AtomicBool::new(self.zero_rtt.load(Ordering::Relaxed)),
            places: PhantomData,
        }
    }
}

impl<T, L, S: Clone, I, C: CredentialPointer<StreamWriterCredential> + Clone> Clone
    for SharedStreamSend<T, L, S, I, C>
{
    fn clone(&self) -> Self {
        Self {
            layer: self.layer.clone(),
            credential: self.credential.clone(),
            reclaim: self.reclaim,
            places: PhantomData,
        }
    }
}

impl<T, L, S: Clone, I, C: CredentialPointer<StreamReaderCredential> + Clone, Ro> Clone
    for SharedStreamReceive<T, L, S, I, C, Ro>
{
    fn clone(&self) -> Self {
        Self {
            layer: self.layer.clone(),
            credential: self.credential.clone(),
            reclaim: self.reclaim,
            zero_rtt: AtomicBool::new(self.zero_rtt.load(Ordering::Relaxed)),
            places: PhantomData,
        }
    }
}

/// Nothing of it is pinned.
impl<T, L, S, I, C: CredentialPointer<StreamWriterCredential>> Unpin
    for SharedStreamSend<T, L, S, I, C>
{
}

/// Nothing of it is pinned.
impl<T, L, S, I, C: CredentialPointer<StreamReaderCredential>, Ro> Unpin
    for SharedStreamReceive<T, L, S, I, C, Ro>
{
}

/// The last holder of the credential hands it back, and the writer gives
/// the stream up; once the layer ended, nothing is done.
impl<T, L, S, I, C: CredentialPointer<StreamWriterCredential>> Drop
    for SharedStreamSend<T, L, S, I, C>
{
    fn drop(&mut self) {
        if let Some(credential) = self.credential.take().and_then(C::into_credential) {
            (self.reclaim)(&self.layer, credential);
        }
    }
}

/// The last holder of the credential hands it back, and the reader gives
/// the reading up; once the layer ended, nothing is done.
impl<T, L, S, I, C: CredentialPointer<StreamReaderCredential>, Ro> Drop
    for SharedStreamReceive<T, L, S, I, C, Ro>
{
    fn drop(&mut self) {
        if let Some(credential) = self.credential.take().and_then(C::into_credential) {
            (self.reclaim)(&self.layer, credential);
        }
    }
}

impl<T, L, S, I, C: CredentialPointer<StreamWriterCredential>> fmt::Debug
    for SharedStreamSend<T, L, S, I, C>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedStreamSend")
            .field("id", &self.stream_id())
            .finish_non_exhaustive()
    }
}

impl<T, L, S, I, C: CredentialPointer<StreamReaderCredential>, Ro> fmt::Debug
    for SharedStreamReceive<T, L, S, I, C, Ro>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedStreamReceive")
            .field("id", &self.stream_id())
            .finish_non_exhaustive()
    }
}

/// A writer through the shared connection turns into one with a shared
/// credential, which can be cloned.
impl<T, L, S: Clone, I, O> StreamWriter<SharedStreamSend<T, L, S, I, StreamWriterCredential>, O> {
    /// The same writer with the credential behind the shared pointer `Q`
    /// ([`SharedStreamSend::into_shared`]).
    pub fn into_shared<Q>(self) -> StreamWriter<SharedStreamSend<T, L, S, I, Q>, O>
    where
        Q: CredentialPointer<StreamWriterCredential> + From<StreamWriterCredential>,
    {
        self.map_share(SharedStreamSend::into_shared)
    }
}

/// A reader through the shared connection turns into one with a shared
/// credential, which can be cloned.
impl<T, L, S: Clone, I, Ro>
    StreamReader<SharedStreamReceive<T, L, S, I, StreamReaderCredential, Ro>>
{
    /// The same reader with the credential behind the shared pointer `Q`
    /// ([`SharedStreamReceive::into_shared`]).
    pub fn into_shared<Q>(self) -> StreamReader<SharedStreamReceive<T, L, S, I, Q, Ro>>
    where
        Q: CredentialPointer<StreamReaderCredential> + From<StreamReaderCredential>,
    {
        StreamReader::new(self.share.into_shared())
    }
}

// ---- opening, accepting, and handing the credentials back ----

/// What a lend of the layer takes to open, accept and hand back: the stream
/// set, and the send strategy's publisher it is lent.
pub type HeldSetTakes<T, L> = HList![StreamsOf<T, L>, SendStrategyPublisher<PublisherOf<T, L>>];

/// The sending capability the handle of an established layer opens and
/// accepts, at the places `I`.
type SendOf<T, L, S, I> = SharedStreamSend<T, L, S, I, StreamWriterCredential>;

/// The receiving capability, as [`SendOf`], on the side of the layer's
/// selection `A`.
type ReceiveOf<T, L, S, I, A> =
    SharedStreamReceive<T, L, S, I, StreamReaderCredential, <A as LayerSelection>::Role>;

/// The places of the components and of the stream intents, as the
/// capabilities name them.
type Places<Ie, Ic, Ir, Is, In, I> = (Ie, Ic, Ir, Is, In, I);

/// Lend the layer `layer` once to `op`, with the stream set
/// and the send strategy's publisher it is lent; what the set did there is
/// handed on at the connection afterwards. Otherwise how the layer ended.
fn with_held_set<T, L, S, R, Ie, Ic, Ir, Is, In, I>(
    layer: &SharedEstablishedLayer<S>,
    op: impl FnOnce(&mut StreamsOf<T, L>, &mut PublisherOf<T, L>) -> R,
) -> Result<R, LayerEndedError<CloseCauseOf<T, L>>>
where
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
{
    layer
        .lend_layer::<T, L, _, Ie, Ic, Ir>(|lineage, _| {
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

/// Opening, accepting and handing back, written once for every stream set.
///
/// `Ie`, `Ic` and `Ir` are where the connection handle's state is in the
/// layer's lineage and in the connection node's, and where version 1's part
/// is in what the parts keep after the end; `Is` and `In` where the stream
/// set and the send strategy's publisher are in the layer's lineage, `I`
/// the place of the stream intents in the composition's sum of intents.
impl<T, L, S, A> EstablishedLayerHandle<T, L, S, A> {
    /// Hand the writer's `credential` back to the stream set.
    fn reclaim_writer<Ie, Ic, Ir, Is, In, I>(
        layer: &SharedEstablishedLayer<S>,
        credential: StreamWriterCredential,
    ) where
        T: V1Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>: HostSendStrategyTypes,
        StreamSetFamilyOf<T>:
            ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
        let _ = with_held_set::<T, L, S, _, Ie, Ic, Ir, Is, In, I>(layer, |set, publish| {
            set.reclaim_writer::<I, _>(publish, credential);
        });
    }

    /// Hand the reader's `credential` back to the stream set.
    fn reclaim_reader<Ie, Ic, Ir, Is, In, I>(
        layer: &SharedEstablishedLayer<S>,
        credential: StreamReaderCredential,
    ) where
        T: V1Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>: HostSendStrategyTypes,
        StreamSetFamilyOf<T>:
            ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
        let _ = with_held_set::<T, L, S, _, Ie, Ic, Ir, Is, In, I>(layer, |set, publish| {
            set.reclaim_reader::<I, _>(publish, credential);
        });
    }

    /// The writer of `id`.
    #[allow(clippy::type_complexity)] // a writer of five type parameters
    fn held_writer<Ie, Ic, Ir, Is, In, I>(
        &self,
        id: StreamId,
    ) -> StreamWriter<SendOf<T, L, S, Places<Ie, Ic, Ir, Is, In, I>>, NoSendOptions>
    where
        T: V1Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>: HostSendStrategyTypes,
        StreamSetFamilyOf<T>:
            ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
        StreamWriter::new(SharedStreamSend::new(
            self.reach().clone(),
            StreamWriterCredential::new(id),
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
        T: V1Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>: HostSendStrategyTypes,
        StreamSetFamilyOf<T>:
            ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
        StreamReader::new(SharedStreamReceive::new(
            self.reach().clone(),
            StreamReaderCredential::new(id),
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
        T: V1Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>: HostSendStrategyTypes,
        StreamSetFamilyOf<T>:
            ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
        with_held_set::<T, L, S, _, Ie, Ic, Ir, Is, In, I>(self.reach(), |set, publish| {
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
        T: V1Choices,
        L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>: HostSendStrategyTypes,
        StreamSetFamilyOf<T>:
            ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
        with_held_set::<T, L, S, _, Ie, Ic, Ir, Is, In, I>(self.reach(), |set, _| {
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
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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

// ---- the operations of the capabilities ----

/// The stream set of `T` and `L`, as the capabilities name it.
type HeldSetOf<T, L> = StreamsOf<T, L>;

/// The failure of a read through the shared connection, in the stream set
/// of `T` and `L`.
type SharedReadErrorOf<T, L> =
    ReadError<
        <HeldSetOf<T, L> as StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
        >>::ReceiveTerminationReason,
        CloseCauseOf<T, L>,
        <StreamResetsOfParts<L> as StreamResets>::Remote,
    >;

/// What the operations of a sending capability reach, whatever the stream
/// set: the layer is lent once, with the set and the send strategy's
/// publisher it is lent, and the set finds the part by the stream's ID the
/// credential lent to it names; what the set published there is handed on
/// at the connection afterwards. Once the layer ended, how it ended.
///
/// `C` lends the credential it points to
/// ([`CredentialPointer::credential`]), as the credential itself,
/// [`Arc`](alloc::sync::Arc) and [`Rc`](alloc::rc::Rc) do.
impl<T, L, S, C, Ie, Ic, Ir, Is, In, I> SharedStreamSend<T, L, S, (Ie, Ic, Ir, Is, In, I), C>
where
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer<StreamWriterCredential>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
{
    /// Lend the layer once to `op`, with the stream set, the publisher it
    /// is lent and the part this capability holds; otherwise how the layer
    /// ended.
    fn with_held<R>(
        &self,
        op: impl FnOnce(&mut HeldSetOf<T, L>, &mut PublisherOf<T, L>, &StreamWriterCredential) -> R,
    ) -> Result<R, LayerEndedError<CloseCauseOf<T, L>>> {
        // invariant: the credential leaves the capability only when it is
        // dropped or turned into another
        let Some(pointer) = self.credential.as_ref() else {
            return Err(held_part_gone(None));
        };
        let held = pointer.credential();
        with_held_set::<T, L, S, _, Ie, Ic, Ir, Is, In, I>(&self.layer, |set, publish| {
            op(set, publish, held)
        })
    }

    /// Resets the stream as `request` asks, a request of the reset kind
    /// ([`StreamResets::ResetRequest`]), through the stream set
    /// ([`StreamSet::reset_with`]). A part that adds the request gives the
    /// writer its capability through this.
    ///
    /// # Errors
    ///
    /// As [`StreamSet::reset_with`], and how the layer ended.
    pub fn reset_with(
        &mut self,
        request: <StreamResetsOfParts<L> as StreamResets>::ResetRequest,
    ) -> Result<(), <StreamResetsOfParts<L> as StreamResets>::ResetRequestError<CloseCauseOf<T, L>>>
    {
        self.with_held(|set, publish, held| set.reset_with::<I, _>(publish, held, request))
            .unwrap_or_else(|ended| Err(ended.into()))
    }
}

/// What the operations of a receiving capability reach, as for a sending
/// one; each also keeps whether the stream had data in 0-RTT packets.
impl<T, L, S, C, Ie, Ic, Ir, Is, In, I, Ro>
    SharedStreamReceive<T, L, S, (Ie, Ic, Ir, Is, In, I), C, Ro>
where
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer<StreamReaderCredential>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
{
    /// Lend the layer once to `op`, as [`SharedStreamSend::with_held`]
    /// does, after keeping whether the stream had data in 0-RTT packets.
    fn with_held<R>(
        &self,
        op: impl FnOnce(&mut HeldSetOf<T, L>, &mut PublisherOf<T, L>, &StreamReaderCredential) -> R,
    ) -> Result<R, LayerEndedError<CloseCauseOf<T, L>>> {
        // invariant: as for the sending capability
        let Some(pointer) = self.credential.as_ref() else {
            return Err(held_part_gone(None));
        };
        let held = pointer.credential();
        with_held_set::<T, L, S, _, Ie, Ic, Ir, Is, In, I>(&self.layer, |set, publish| {
            if set.received_zero_rtt(held) {
                self.zero_rtt.store(true, Ordering::Relaxed);
            }
            op(set, publish, held)
        })
    }
}

/// A writer through the shared connection writes through the stream set,
/// whatever it is ([`StreamSet::poll_write`] and the others).
impl<T, L, S, C, Ie, Ic, Ir, Is, In, I> StreamWrite
    for SharedStreamSend<T, L, S, (Ie, Ic, Ir, Is, In, I), C>
where
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer<StreamWriterCredential>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
{
    type Parameters = SendParametersOf<T>;
    type Destination = AnyActiveLinkPath;
    type CloseCause = CloseCauseOf<T, L>;
    type WriteLimitReason = <HeldSetOf<T, L> as StreamSet<
        CloseCauseOf<T, L>,
        SendTypes<T, L>,
        StreamResetsOfParts<L>,
    >>::WriteLimitReason;

    fn poll_write_with<B: Buf + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &SendParametersOf<T>,
        destination: &AnyActiveLinkPath,
    ) -> Poll<Result<WriteReport, WriteError<Self::WriteLimitReason, CloseCauseOf<T, L>>>> {
        self.with_held(|set, publish, held| {
            set.poll_write::<I, _, B>(publish, held, cx, input, parameters, destination)
        })
        .unwrap_or_else(|ended| Poll::Ready(Err(ended.into())))
    }

    fn close(&mut self) -> Result<(), CloseError<CloseCauseOf<T, L>>> {
        self.with_held(|set, publish, held| set.close::<I, _>(publish, held))
            .unwrap_or_else(|ended| Err(ended.into()))
    }

    fn reset(&mut self, code: ApplicationErrorCode) -> Result<(), ResetError<CloseCauseOf<T, L>>> {
        self.with_held(|set, publish, held| set.reset::<I, _>(publish, held, code))
            .unwrap_or_else(|ended| Err(ended.into()))
    }

    fn flush(&mut self) -> impl Future<Output = Result<(), FlushError<CloseCauseOf<T, L>>>> {
        poll_fn(|cx| {
            self.with_held(|set, _, held| set.poll_flushed(held, cx))
                .unwrap_or_else(|ended| Poll::Ready(Err(ended.into())))
        })
    }

    fn all_acknowledged(
        &mut self,
    ) -> impl Future<Output = Result<(), AllAcknowledgedError<CloseCauseOf<T, L>>>> {
        poll_fn(|cx| {
            self.with_held(|set, _, held| set.poll_all_acknowledged(held, cx))
                .unwrap_or_else(|ended| Poll::Ready(Err(ended.into())))
        })
    }
}

/// A reader through the shared connection stops through the stream set.
impl<T, L, S, C, Ie, Ic, Ir, Is, In, I, Ro> StreamRead
    for SharedStreamReceive<T, L, S, (Ie, Ic, Ir, Is, In, I), C, Ro>
where
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer<StreamReaderCredential>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
{
    type CloseCause = CloseCauseOf<T, L>;

    fn stop(&mut self, code: ApplicationErrorCode) -> Result<(), StopError<CloseCauseOf<T, L>>> {
        self.with_held(|set, publish, held| set.stop::<I, _>(publish, held, code))
            .unwrap_or_else(|ended| Err(ended.into()))
    }
}

/// A reader through the shared connection reads through the stream set.
impl<T, L, S, C, Ie, Ic, Ir, Is, In, I, Ro> Read
    for StreamReader<SharedStreamReceive<T, L, S, (Ie, Ic, Ir, Is, In, I), C, Ro>>
where
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer<StreamReaderCredential>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
{
    type Error = SharedReadErrorOf<T, L>;

    fn poll_read<'visit, Output: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        destination: &mut Output,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        host.get_pin_mut()
            .get_mut()
            .share
            .with_held(|set, publish, held| {
                set.poll_read_into::<I, _, Output>(publish, held, cx, destination)
            })
            .unwrap_or_else(|ended| Poll::Ready(Err(ended.into())))
    }
}

/// A reader through the shared connection reads blocks through the stream
/// set, cut at the maximum.
impl<T, L, S, C, Ie, Ic, Ir, Is, In, I, Ro> ReadChunk
    for StreamReader<SharedStreamReceive<T, L, S, (Ie, Ic, Ir, Is, In, I), C, Ro>>
where
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer<StreamReaderCredential>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
{
    type Chunk = <HeldSetOf<T, L> as StreamSet<
        CloseCauseOf<T, L>,
        SendTypes<T, L>,
        StreamResetsOfParts<L>,
    >>::Chunk;

    fn poll_read_chunk<'visit>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<Self::Chunk>, Self::Error>>
    where
        Self: 'visit,
    {
        host.get_pin_mut()
            .get_mut()
            .share
            .with_held(|set, publish, held| set.poll_read_chunk::<I, _>(publish, held, cx, maximum))
            .unwrap_or_else(|ended| Poll::Ready(Err(ended.into())))
    }
}

/// A server's reader through the shared connection tells whether the
/// stream had data in 0-RTT packets; a client's has no such method:
///
/// ```compile_fail,E0599
/// # use sakuya_connection::v1::application_handles::{
/// #     shared_stream::SharedStreamReceive, stream::StreamReader,
/// # };
/// # use kasen_handshake::role::Client;
/// fn ask<T, L, S, I, C>(reader: &StreamReader<SharedStreamReceive<T, L, S, I, C, Client>>) -> bool
/// where
///     C: sakuya_connection::v1::application_handles::credential::CredentialPointer<
///         sakuya_connection::v1::streams::StreamReaderCredential,
///     >,
/// {
///     reader.received_zero_rtt()
/// }
/// ```
impl<T, L, S, C, Ie, Ic, Ir, Is, In, I>
    StreamReader<SharedStreamReceive<T, L, S, (Ie, Ic, Ir, Is, In, I), C, role::Server>>
where
    T: V1Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer<StreamReaderCredential>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
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
{
    /// Whether a STREAM frame of the stream arrived in a 0-RTT packet and
    /// was taken: data the client sent in 0-RTT, which an attacker may
    /// replay (RFC 9001 §9.2), as the stream set tells it
    /// ([`StreamSet::received_zero_rtt`]). Once the layer ended, as this
    /// reader last read it from the set; every read and stop reads it too.
    pub fn received_zero_rtt(&self) -> bool {
        self.share
            .with_held(|set, _, held| set.received_zero_rtt(held))
            .unwrap_or_else(|_| self.share.zero_rtt.load(Ordering::Relaxed))
    }
}
