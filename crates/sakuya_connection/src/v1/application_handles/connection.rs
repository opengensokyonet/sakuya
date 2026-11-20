//! The connection handle ([`ConnectionHandle`]), the state of the
//! connection node it reads ([`ConnectionHandleState`]), what the state
//! keeps once the connection ended ([`ConnectionHandleRemains`]), and the
//! results of the handshake it gives ([`ClientHandshakeFacts`],
//! [`ServerHandshakeFacts`]).
//!
//! The state is a data component of the connection node. It is written by
//! what happens in the connection:
//!
//! - the record of why the connection closed: once written, the state
//!   keeps its reason, lets the exporter go, and every wait that has not
//!   ended ends with it;
//! - the advancing call: a client's ClientHello written settles whether
//!   it has a layer before the handshake completes, which it has when it
//!   sends 0-RTT, with the application protocol of the ticket; a server's
//!   ServerHello written keeps the selected target for the layer; the
//!   handshake completed keeps the facts and the exporter;
//! - the stream set of the established layer: built, it has the state give
//!   the layer its identity, which is the layer the connection has now;
//!   ended, it has the layer's end kept. The state gives the layer's handle
//!   once the layer was built and the handshake's selection came, in
//!   whichever order.
//!
//! The connection handle holds the connection in its wrapper
//! ([`SharedConnection`]) and nothing else: each of its operations borrows
//! the connection once and is lent the connection node
//! ([`LendNode::lend`]). A wait reads the state and keeps its waker there
//! until the state changes. Once the connection ended, the state is gone,
//! and the waits read what it kept ([`ConnectionHandleRemains`], the part's
//! [`LayerShare::Remains`](crate::share::LayerShare::Remains)).
//!
//! What a wait gives depends on what happened, not on when it is called
//! (application-handles «连接先结束时各个等待的结果»): a handshake that
//! completed gives `Ok` also once the connection closed, and so does the
//! established layer's handle, whose operations then report the end.
//!
//! The state is made together with the record, and takes the record's
//! reason also when the connection node ends: a connection that ends at
//! once where its reason is written ends before the state reads the record
//! again. When the connection's future is dropped, the state takes the
//! reason the record has then, [`CloseReason::Aborted`] unless one was
//! written before; after a panic, which runs no end action, it also ends
//! the layer the connection has. The stream set and the datagram queues
//! hear of the panic themselves, in their own layer
//! ([`StreamSet::driver_panicked`](crate::v1::streams::StreamSet::driver_panicked)).

use alloc::{sync::Arc, vec::Vec};
use core::{
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use nitori_tls::{
    client::engine::{EarlyDataOutcome, ServerIdentity},
    extension::alpn::ProtocolName,
    server::targets::SelectedTarget,
};
use sakuya_stream_v1::connection::{AbortCause, CloseReason, ConnectionClosedError, LayerEnd};
use sakuya_wire::parts::Selector;

use super::established_layer::EstablishedLayerHandle;
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    component_event::{EventSubscriptions, TriggeredEvents},
    driver::{LendNode, NotLent},
    error::{ConnectionErrorOf, ConnectionErrorsOf},
    layer,
    others::OtherNodes,
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::GetAt,
    v1::{
        ApplicationErrorOf, Choices, CloseCauseOf, EventsOf, Side,
        close::{CloseReasonRecord, TransportClose},
        close_request::close_into_record,
        component_events::CloseReasonWritten,
        events::ConnectionEventSink,
        sending::DatagramAcceptance,
    },
};

#[cfg(test)]
mod tests;

/// What a client knows of its handshake once it completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHandshakeFacts {
    /// Who the server is.
    pub identity: ServerIdentity,
    /// The application protocol the server selected.
    pub application_protocol: Option<ProtocolName<Bytes>>,
    /// What became of 0-RTT.
    pub early_data: EarlyDataOutcome,
}

/// What a server knows of its handshake once it completed; `T` is the type
/// of the selected target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHandshakeFacts<T> {
    /// The selected target and application protocol.
    pub selected: SelectedTarget<T>,
    /// Whether the client authenticated with the PSK of a ticket.
    pub resumed: bool,
}

/// Keep `waker` among `wakers`, unless one there wakes the same task.
pub fn keep_waker(wakers: &mut Vec<Waker>, waker: &Waker) {
    if !wakers.iter().any(|kept| kept.will_wake(waker)) {
        wakers.push(waker.clone());
    }
}

/// Wake every waker of `wakers`, which is left empty.
pub fn wake_all(wakers: &mut Vec<Waker>) {
    for waker in core::mem::take(wakers) {
        waker.wake();
    }
}

/// The identity of an established layer among the layers of one
/// connection (`LayerId`): the layers are counted as they are built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerId(u64);

/// What the state keeps of one established layer whose handle it gave.
struct LayerRecord<A, C> {
    id: LayerId,
    /// What the layer runs with of the handshake's selection.
    selection: Arc<A>,
    /// How the layer ended, once it did.
    end: Option<LayerEnd<C>>,
}

/// Whether the connection had an established layer before its handshake
/// completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EarlyLayer {
    /// Not settled yet.
    Undecided,
    /// It had none.
    Absent,
    /// It had this one.
    Present(LayerId),
}

/// What the connection handle's state keeps after the connection ended
/// (`ConnectionHandleRemains`): the reason it closed for, the facts of
/// the handshake when it completed, whether it had a layer before the
/// handshake completed, and the identity, selection and end of each layer
/// whose handle was given. Version 1's part of what the parts keep after
/// the end ([`RemainsOf`]).
///
/// `C` is this endpoint's reason for closing, `F` the facts of the side's
/// handshake, `A` what a layer runs with of the handshake's selection. The
/// live state answers the waits from the same records.
pub struct ConnectionHandleRemains<C, F, A> {
    /// The reason the connection closed for, once the record has one.
    closed: Option<CloseReason<C>>,
    /// The facts of the handshake, once it completed.
    facts: Option<F>,
    early: EarlyLayer,
    /// The latest layer whose handle was given.
    layer: Option<LayerId>,
    layers: Vec<LayerRecord<A, C>>,
}

/// Nothing happened yet.
impl<C, F, A> Default for ConnectionHandleRemains<C, F, A> {
    fn default() -> Self {
        Self {
            closed: None,
            facts: None,
            early: EarlyLayer::Undecided,
            layer: None,
            layers: Vec::new(),
        }
    }
}

/// It shows how far the connection got, not what it holds.
impl<C, F, A> fmt::Debug for ConnectionHandleRemains<C, F, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionHandleRemains")
            .field("handshake_completed", &self.facts.is_some())
            .field("layers", &self.layers.len())
            .field("closed", &self.closed.is_some())
            .finish()
    }
}

/// The result of a wait on the handshake or on a layer's handle, or `None`
/// while it waits.
type Waited<R, C> = Option<Result<R, ConnectionClosedError<C>>>;

impl<C, F, A> ConnectionHandleRemains<C, F, A> {
    /// The record of the layer `id`.
    fn record(&self, id: LayerId) -> Option<&LayerRecord<A, C>> {
        self.layers.iter().find(|record| record.id == id)
    }

    /// The layer `id` with its selection.
    fn given(&self, id: LayerId) -> Option<(LayerId, Arc<A>)> {
        self.record(id)
            .map(|record| (id, Arc::clone(&record.selection)))
    }

    /// The connection closed: `Err` with the reason.
    fn closed_error<R>(&self) -> Waited<R, C> {
        self.closed
            .as_ref()
            .map(|reason| Err(ConnectionClosedError::new(reason.clone())))
    }

    fn closed(&self) -> Option<CloseReason<C>> {
        self.closed.clone()
    }

    fn handshake_completed(&self) -> Waited<F, C>
    where
        F: Clone,
    {
        match &self.facts {
            Some(facts) => Some(Ok(facts.clone())),
            None => self.closed_error(),
        }
    }

    fn early(&self) -> Waited<Option<(LayerId, Arc<A>)>, C> {
        match self.early {
            EarlyLayer::Present(id) => self.given(id).map(|given| Ok(Some(given))),
            EarlyLayer::Absent => Some(Ok(None)),
            EarlyLayer::Undecided => self.closed_error(),
        }
    }

    fn established(&self) -> Waited<(LayerId, Arc<A>), C> {
        match (&self.facts, self.layer) {
            (Some(_), Some(id)) => self.given(id).map(Ok),
            // a handshake that completed without its layer, or did not
            // complete, before the connection closed
            _ => self.closed_error(),
        }
    }

    /// The exporter `exporter` once the handshake completed.
    fn exporter<X>(&self, exporter: &Option<Arc<X>>) -> Waited<Option<Arc<X>>, C> {
        match &self.facts {
            Some(_) => Some(Ok(exporter.clone())),
            None => self.closed_error(),
        }
    }

    /// How the layer `id` ended, once it did.
    pub fn layer_end(&self, id: LayerId) -> Option<LayerEnd<C>> {
        self.record(id)?.end.clone()
    }

    /// What is kept once the connection ended: the reason is there, and
    /// every layer that did not end ended with it.
    ///
    /// A connection ends where its reason is written or once the record
    /// that has one asks for it, and a dropped future writes it before any
    /// node ends, so the reason is there unless the parts kept nothing.
    pub(crate) fn ended(&mut self) -> &Self {
        let reason = self.closed.get_or_insert_with(|| {
            debug_assert!(false, "the connection ended without a reason kept");
            CloseReason::Aborted(AbortCause::DriverDropped)
        });
        for record in &mut self.layers {
            record
                .end
                .get_or_insert_with(|| LayerEnd::ConnectionClosed(reason.clone()));
        }
        self
    }
}

/// The state of the connection node that the connection handle reads
/// (`ConnectionHandleState`); see the [module documentation](self).
///
/// `C` is this endpoint's reason for closing, `F` the facts of the side's
/// handshake, `X` its exporter, `A` what an established layer runs with of
/// the handshake's selection. Every wait keeps its waker here, and every
/// change wakes them all.
pub struct ConnectionHandleState<C, F, X, A> {
    /// What is kept after the connection ended.
    kept: ConnectionHandleRemains<C, F, A>,
    /// The exporter, from the handshake's completion until the connection
    /// closes.
    exporter: Option<Arc<X>>,
    /// What the handshake selected the next layer to run with, once it
    /// did.
    selection: Option<A>,
    /// The layer built whose handle waits for its selection.
    built: Option<LayerId>,
    /// The layer the connection has now.
    current: Option<LayerId>,
    /// How many layers were built.
    layers_built: u64,
    /// Whether the application took the handle of the layer before the
    /// handshake completed: a client's application asks for 0-RTT so
    /// (RFC 9001 §5.6).
    early_taken: bool,
    wakers: Vec<Waker>,
}

impl<C, F, X, A> ConnectionHandleState<C, F, X, A> {
    /// The state of a connection where nothing has happened yet.
    pub fn new() -> Self {
        Self {
            kept: ConnectionHandleRemains::default(),
            exporter: None,
            selection: None,
            built: None,
            current: None,
            layers_built: 0,
            early_taken: false,
            wakers: Vec::new(),
        }
    }

    /// Whether the application took the handle of the layer before the
    /// handshake completed.
    pub(crate) fn early_taken(&self) -> bool {
        self.early_taken
    }

    /// Change the state with `change`, and wake every waiter.
    fn change(&mut self, change: impl FnOnce(&mut Self)) {
        change(self);
        wake_all(&mut self.wakers);
    }

    /// Keep `waker` until the state changes.
    pub(crate) fn keep_waker(&mut self, waker: &Waker) {
        keep_waker(&mut self.wakers, waker);
    }

    /// What is kept after the connection ended, as it is now.
    pub(crate) fn kept(&self) -> &ConnectionHandleRemains<C, F, A> {
        &self.kept
    }

    /// Whether `id` is the layer the connection has now.
    pub(crate) fn is_current(&self, id: LayerId) -> bool {
        self.current == Some(id)
    }

    /// The layer built last: the one the connection has, or, once it ended,
    /// the one that ended last. Read by a part of the established layer as
    /// the layer ends, whatever the order of the parts' end actions.
    pub fn latest_layer(&self) -> Option<LayerId> {
        self.layers_built.checked_sub(1).map(LayerId)
    }

    /// Give the layer built once its selection came.
    fn give_when_complete(&mut self) {
        if self.built.is_none() || self.selection.is_none() {
            return;
        }
        let (Some(id), Some(selection)) = (self.built.take(), self.selection.take()) else {
            return;
        };
        self.kept.layers.push(LayerRecord {
            id,
            selection: Arc::new(selection),
            end: None,
        });
        // the layer before the handshake completed when it has not
        if self.kept.early == EarlyLayer::Undecided {
            self.kept.early = match self.kept.facts {
                None => EarlyLayer::Present(id),
                Some(_) => EarlyLayer::Absent,
            };
        }
        self.kept.layer = Some(id);
    }

    // ---- what the connection writes ----

    /// The connection closed for `reason`, the first one in its record: the
    /// state lets its exporter go. Only the first reason is kept.
    pub(crate) fn connection_closed(&mut self, reason: CloseReason<C>) {
        self.change(|state| {
            if state.kept.closed.is_some() {
                return;
            }
            state.kept.closed = Some(reason);
            state.exporter = None;
        });
    }

    /// Whether the state has the reason the connection closed for.
    pub(crate) fn is_closed(&self) -> bool {
        self.kept.closed.is_some()
    }

    /// The hello this side sends first is written, and this side has no
    /// established layer before its handshake completes: a client that
    /// sends no 0-RTT.
    pub(crate) fn no_early_layer(&mut self) {
        self.change(|state| {
            if state.kept.early == EarlyLayer::Undecided {
                state.kept.early = EarlyLayer::Absent;
            }
        });
    }

    /// The next established layer runs with `selection` of the handshake's
    /// selection.
    pub(crate) fn keep_selection(&mut self, selection: A) {
        self.change(|state| {
            state.selection = Some(selection);
            state.give_when_complete();
        });
    }

    /// The handshake completed with `facts` and the connection's exporter,
    /// `None` when the connection let it go already. A connection that
    /// closed already does not keep the exporter.
    pub(crate) fn handshake_completed(&mut self, facts: F, exporter: Option<Arc<X>>) {
        self.change(|state| {
            if state.kept.facts.is_some() {
                return;
            }
            state.exporter = exporter.filter(|_| state.kept.closed.is_none());
            state.kept.facts = Some(facts);
        });
    }

    /// An established layer was built: it is the layer the connection has
    /// now, with an identity of its own. Its handle is given once the
    /// handshake selected what it runs with, as the handle of the layer
    /// before the handshake completed when it has not.
    pub(crate) fn layer_built(&mut self) {
        self.change(|state| {
            let id = LayerId(state.layers_built);
            state.layers_built += 1;
            state.current = Some(id);
            state.built = Some(id);
            state.give_when_complete();
        });
    }

    /// The layer the connection has ended as `end`; only its first end is
    /// kept. A layer whose handle was not given yet gives none.
    pub(crate) fn layer_ended(&mut self, end: LayerEnd<C>) {
        self.change(|state| {
            let Some(id) = state.current.take() else {
                return;
            };
            if state.built == Some(id) {
                state.built = None;
            }
            if let Some(record) = state.kept.layers.iter_mut().find(|record| record.id == id) {
                record.end.get_or_insert(end);
            }
        });
    }
}

impl<C, F, X, A> Default for ConnectionHandleState<C, F, X, A> {
    fn default() -> Self {
        Self::new()
    }
}

/// It shows how far the connection got, not what the state holds.
impl<C, F, X, A> fmt::Debug for ConnectionHandleState<C, F, X, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionHandleState")
            .field("handshake_completed", &self.kept.facts.is_some())
            .field("layer", &self.current.is_some())
            .field("closed", &self.kept.closed.is_some())
            .finish_non_exhaustive()
    }
}

// ---- the types of the choices ----

/// The facts of the handshake of the side of the choices `T`.
pub type HandshakeFactsOf<T> = <<T as crate::v1::MakerChoices>::Side as Side>::HandshakeFacts;

/// What an established layer of the choices `T` runs with of the
/// handshake's selection.
pub type LayerSelectionOf<T> = <<T as crate::v1::MakerChoices>::Side as Side>::LayerSelection;

/// The exporter of the side of the choices `T`.
pub type ExporterOf<T> = <<T as crate::v1::MakerChoices>::Side as Side>::Exporter;

/// The state the connection handle of the choices `T` and the list of
/// parts `L` reads.
pub type ConnectionHandleStateOf<T, L> = ConnectionHandleState<
    CloseCauseOf<T, L>,
    HandshakeFactsOf<T>,
    ExporterOf<T>,
    LayerSelectionOf<T>,
>;

/// What the state of the choices `T` and the list of parts `L` keeps after
/// the connection ended.
pub type ConnectionHandleRemainsOf<T, L> =
    ConnectionHandleRemains<CloseCauseOf<T, L>, HandshakeFactsOf<T>, LayerSelectionOf<T>>;

// ---- the state in the connection node ----

/// The record of why the connection closed and the state are made
/// together: no connection starts closing.
///
/// When the connection node ends, the state takes the record's reason. A
/// connection that ends at once where its reason is written, as at the
/// idle timeout, ends before the state's handler runs; without this end the
/// state would never learn the reason.
impl<T, L> Build<T, L, layer::Connection, ()>
    for frunk_core::HList![
        CloseReasonRecord<CloseCauseOf<T, L>>,
        ConnectionHandleStateOf<T, L>
    ]
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        frunk_core::hlist![CloseReasonRecord::new(), ConnectionHandleState::new()]
    }

    fn end<'v, B: CallBundle>(
        self,
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
    ) {
        let frunk_core::hlist_pat![record, mut state] = self;
        match record.reason() {
            Some(reason) => state.connection_closed(reason.clone()),
            // invariant: the connection ends where its reason is written, or
            // once the record that has one asks for it, and a dropped future
            // writes it before any node ends
            None => debug_assert!(false, "the connection ends without a reason"),
        }
    }
}

/// The state subscribes to the reason for closing written and takes the
/// reason from the record of why the connection closed. When the
/// connection's future is dropped it takes the reason the record has then,
/// or [`CloseReason::Aborted`] with the cause; after a panic, which runs no
/// end action, it also ends the layer the connection has. Once the
/// connection ended, what it keeps goes into version 1's
/// [`ConnectionHandleRemains`].
impl<T, L, I, Ic, Ir> DataComponent<T, L, layer::Connection, (I, Ic, Ir)>
    for ConnectionHandleStateOf<T, L>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<Self, I> + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<CloseReasonWritten>();
    }

    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        if !lineage.get::<Self, I>().is_closed()
            && let Some(reason) = lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .reason()
                .cloned()
        {
            lineage.get_mut::<Self, I>().connection_closed(reason);
        }
        None
    }

    fn future_dropped<'v>(lineage: &mut LineageOf<'v, T, L, layer::Connection>, cause: AbortCause) {
        let reason = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .reason()
            .cloned()
            .unwrap_or(CloseReason::Aborted(cause));
        let mut state = lineage.get_mut::<Self, I>();
        state.connection_closed(reason.clone());
        if cause == AbortCause::Panicked {
            state.layer_ended(LayerEnd::ConnectionClosed(reason));
        }
    }

    fn remains<'v>(
        lineage: &mut LineageOf<'v, T, L, layer::Connection>,
        out: &mut RemainsOf<T, L>,
    ) {
        // the record has the reason by now, the state may not yet
        let reason = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .reason()
            .cloned();
        let mut state = lineage.get_mut::<Self, I>();
        if let Some(reason) = reason {
            state.connection_closed(reason);
        }
        let mut kept = core::mem::take(&mut state.kept);
        kept.ended();
        *Selector::<ConnectionHandleRemainsOf<T, L>, Ir>::get_mut(out) = kept;
        wake_all(&mut state.wakers);
    }
}

// ---- reading the state through the connection ----

/// `Ready` with what `look` finds in what the state of the connection
/// node keeps, and in its exporter, or `Pending` with the waker of `cx`
/// kept in the state until it changes: `connection` is borrowed once, and
/// lent the connection node. Once the connection ended, `look` reads what
/// the state kept, without an exporter, and finds something.
///
/// `I` is where the state is in the connection node's lineage, `Ir` where
/// version 1's part is in what the parts keep after the end.
pub(crate) fn poll_kept<T, L, S, R, I, Ir>(
    connection: &S,
    cx: &mut Context<'_>,
    look: impl Fn(&ConnectionHandleRemainsOf<T, L>, &Option<Arc<ExporterOf<T>>>) -> Option<R>,
) -> Poll<R>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, I>,
{
    connection.with(|driver| {
        let lent = driver.lend::<layer::Connection, _>((), |mut lineage, _| {
            let found = {
                let state = lineage.get::<ConnectionHandleStateOf<T, L>, I>();
                look(&state.kept, &state.exporter)
            };
            if found.is_none() {
                lineage
                    .get_mut::<ConnectionHandleStateOf<T, L>, I>()
                    .keep_waker(cx.waker());
            }
            (found, None)
        });
        match lent {
            Ok(Some(found)) => Poll::Ready(found),
            // the connection node is there from the connection's making on
            Ok(None) | Err(NotLent::Absent) => Poll::Pending,
            Err(NotLent::Ended(remains)) => {
                let kept = Selector::<ConnectionHandleRemainsOf<T, L>, Ir>::get_mut(remains);
                match look(kept.ended(), &None) {
                    Some(found) => Poll::Ready(found),
                    None => {
                        // invariant: with the reason there, every wait finds
                        // its result
                        debug_assert!(false, "a wait finds nothing once the connection ended");
                        Poll::Pending
                    }
                }
            }
        }
    })
}

// ---- the connection handle ----

/// The handle of a connection in the application's hands
/// (`ConnectionHandle`): it asks for the close, and waits for the reason,
/// the handshake's result and the handles of the established layers.
///
/// `T` is the composition's choices, `L` its list of parts, `S` the
/// connection in the wrapper the host chose ([`SharedConnection`]). A clone
/// is the same handle; dropping every handle does not close the connection.
/// Every operation borrows the connection once; the futures of the waits
/// borrow the handle and nothing else, and every task that waits gets the
/// same result.
///
/// The type parameters of the methods are where the components they read
/// are, which the compiler infers.
pub struct ConnectionHandle<T, L, S> {
    connection: S,
    types: PhantomData<fn() -> (T, L)>,
}

impl<T, L, S> ConnectionHandle<T, L, S> {
    /// The handle of `connection`.
    pub fn new(connection: S) -> Self {
        Self {
            connection,
            types: PhantomData,
        }
    }
}

impl<T, L, S> ConnectionHandle<T, L, S>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
{
    /// Ask to close the connection with `error`. When the connection's
    /// record of why it closed has no reason yet, the request becomes the
    /// reason at once; it does not wait for data to be sent, and tells
    /// nothing of which reason is first: that is [`closed`]'s. A client
    /// whose link accepted no datagram of the connection yet ends it at
    /// once, with nothing sent. Once the connection ended, nothing happens.
    ///
    /// [`closed`]: Self::closed
    pub fn close<Ic, Ia, Iev>(&self, error: ApplicationErrorOf<T>)
    where
        ConnectionErrorOf<L>: TransportClose,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
            + GetAt<DatagramAcceptance, Ia>
            + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    {
        self.connection.with(|driver| {
            // an ended connection has nothing to close
            let _ = driver.lend::<layer::Connection, _>((), |mut lineage, now| {
                let request = close_into_record::<T, L, Ic, Ia, Iev>(&mut lineage, error, now);
                ((), request)
            });
        });
    }

    /// The reason the connection closed for, once it did: the first in its
    /// record, the same for every caller.
    pub fn closed<I, Ir>(&self) -> impl Future<Output = CloseReason<CloseCauseOf<T, L>>> + '_
    where
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, I>,
    {
        poll_fn(|cx| poll_kept::<T, L, S, _, I, Ir>(&self.connection, cx, |kept, _| kept.closed()))
    }

    /// The facts of the handshake, once it completed; also after the
    /// connection closed.
    ///
    /// # Errors
    ///
    /// [`ConnectionClosedError`] when the connection closed before the
    /// handshake completed.
    pub fn handshake_completed<I, Ir>(
        &self,
    ) -> impl Future<Output = Result<HandshakeFactsOf<T>, ConnectionClosedError<CloseCauseOf<T, L>>>> + '_
    where
        HandshakeFactsOf<T>: Clone,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, I>,
    {
        poll_fn(|cx| {
            poll_kept::<T, L, S, _, I, Ir>(&self.connection, cx, |kept, _| {
                kept.handshake_completed()
            })
        })
    }

    /// The handle of the established layer before the handshake completed,
    /// once it is settled whether there is one: `None` when the connection
    /// never had one, `Some` when it had, also once the handshake completed.
    /// A server has one from its ServerHello written; a client has one from
    /// its ClientHello written when it sends 0-RTT. A client that takes it
    /// asks for 0-RTT (RFC 9001 §5.6): its close before the handshake
    /// completes then goes in a 0-RTT packet too.
    ///
    /// # Errors
    ///
    /// [`ConnectionClosedError`] when the connection closed before it was
    /// settled.
    #[allow(clippy::type_complexity)]
    pub fn early<I, Ir>(
        &self,
    ) -> impl Future<
        Output = Result<
            Option<EstablishedLayerHandle<T, L, S, LayerSelectionOf<T>>>,
            ConnectionClosedError<CloseCauseOf<T, L>>,
        >,
    > + '_
    where
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, I>,
    {
        poll_fn(|cx| {
            let taken = poll_kept::<T, L, S, _, I, Ir>(&self.connection, cx, |kept, _| {
                kept.early()
                    .map(|early| early.map(|given| given.map(|given| self.layer(given))))
            });
            if let Poll::Ready(Ok(Some(_))) = &taken {
                // an ended connection has nothing left to mark
                self.connection.with(|driver| {
                    let _ = driver.lend::<layer::Connection, _>((), |mut lineage, _| {
                        lineage
                            .get_mut::<ConnectionHandleStateOf<T, L>, I>()
                            .early_taken = true;
                        ((), None)
                    });
                });
            }
            taken
        })
    }

    /// The handle of the established layer once the handshake completed;
    /// also after the connection closed, when the layer's operations report
    /// its end.
    ///
    /// # Errors
    ///
    /// [`ConnectionClosedError`] when the connection closed before the
    /// handshake completed.
    #[allow(clippy::type_complexity)]
    pub fn established<I, Ir>(
        &self,
    ) -> impl Future<
        Output = Result<
            EstablishedLayerHandle<T, L, S, LayerSelectionOf<T>>,
            ConnectionClosedError<CloseCauseOf<T, L>>,
        >,
    > + '_
    where
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, I>,
    {
        poll_fn(|cx| {
            poll_kept::<T, L, S, _, I, Ir>(&self.connection, cx, |kept, _| {
                kept.established()
                    .map(|established| established.map(|given| self.layer(given)))
            })
        })
    }

    /// The exporter of the handshake, once it completed: the connection's
    /// own, shared, until the connection closes, and `None` afterwards. A
    /// clone kept may be used after the connection closed.
    ///
    /// # Errors
    ///
    /// [`ConnectionClosedError`] when the connection closed before the
    /// handshake completed.
    #[allow(clippy::type_complexity)]
    pub fn exporter<I, Ir>(
        &self,
    ) -> impl Future<
        Output = Result<Option<Arc<ExporterOf<T>>>, ConnectionClosedError<CloseCauseOf<T, L>>>,
    > + '_
    where
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, I>,
    {
        poll_fn(|cx| {
            poll_kept::<T, L, S, _, I, Ir>(&self.connection, cx, |kept, exporter| {
                kept.exporter(exporter)
            })
        })
    }

    /// The handle of the layer `id`, which runs with `selection`.
    fn layer(
        &self,
        (id, selection): (LayerId, Arc<LayerSelectionOf<T>>),
    ) -> EstablishedLayerHandle<T, L, S, LayerSelectionOf<T>> {
        EstablishedLayerHandle::new(self.connection.clone(), id, selection)
    }
}

/// A clone is the same handle.
impl<T, L, S: Clone> Clone for ConnectionHandle<T, L, S> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            types: PhantomData,
        }
    }
}

impl<T, L, S> fmt::Debug for ConnectionHandle<T, L, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionHandle").finish_non_exhaustive()
    }
}
