//! The connection handle ([`ConnectionHandle`]), the cell it shares with
//! the connection node ([`ConnectionHandleCell`]), and the results of the
//! handshake it gives ([`ClientHandshakeFacts`], [`ServerHandshakeFacts`]).
//!
//! The cell is a data component of the connection node; the connection
//! handle and the node keep clones of it, both taken from the slot the
//! connection was made with ([`ConnectionArgs::connection_handle`],
//! [`ConnectionHandleCellSlot`]). It is written by
//! what happens in the connection and read by the application:
//!
//! - the record of why the connection closed: once written, the cell keeps
//!   its reason, lets the exporter go, and every wait that has not ended
//!   ends with it;
//! - the advancing call: a client's ClientHello written settles that it
//!   has no layer before the handshake completes (this version sends no
//!   0-RTT); a server's ServerHello written keeps the selected target for
//!   the layer; the handshake completed keeps the facts and the exporter;
//! - the stream set of the established layer: built, it hands the cell what
//!   the layer's handle needs; ended, the layer's end.
//!
//! What a wait gives depends on what happened, not on when it is called
//! (application-handles «连接先结束时各个等待的结果»): a handshake that
//! completed gives `Ok` also once the connection closed, and so does the
//! established layer's handle, whose operations then report the end.
//!
//! The cell is made together with the record, and takes the record's
//! reason also when the connection node ends: a connection that ends at
//! once where its reason is written ends before the cell reads the record
//! again. When the connection's future is dropped, the cell takes the
//! reason the record has then, [`CloseReason::Aborted`] unless one was
//! written before.
//! After a panic, no end action runs: the cell also ends the layer whose
//! handle it gave, and the waits on that handle end; the streams' do not.

use core::{
    any::Any,
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    task::{Context, Poll, Waker},
};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use bytes::Bytes;
use sakuya_stream::connection::{AbortCause, CloseReason, ConnectionClosedError, LayerEnd};
use sakuya_tls::{
    client::engine::{EarlyDataOutcome, ServerIdentity},
    extension::alpn::ProtocolName,
    server::targets::SelectedTarget,
};
use sakuya_wire::parts::Selector;

use super::established_layer::{EstablishedLayerHandle, LayerShare};
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    error::ConnectionErrorsOf,
    layer,
    others::OtherNodes,
    send_strategy::{AnyActiveLinkPath, SendStrategy},
    share::{ConnectionArgsOf, LineageLists, LineagePartList, LogicalPathKeys},
    take::GetAt,
    v1::{
        Choices, CloseCauseOf, ConnectionArgs, Side,
        close::CloseReasonRecord,
        close_request::CloseRequestCell,
        send::SendTypes,
        send_planning::{IntakeOf, IntakePublishOutcome, SendStrategyOf},
        streams::{
            StreamSet, StreamsOf,
            send::{StreamIntent, StreamIntentTicketOf},
        },
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

/// What locking `mutex` gives, whether or not a holder panicked: a holder
/// panics only on a broken invariant of its own, and the state is taken as
/// it was left.
pub(crate) fn lock<X>(mutex: &Mutex<X>) -> MutexGuard<'_, X> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Keep `waker` among `wakers`, unless one there wakes the same task.
pub(crate) fn keep_waker(wakers: &mut Vec<Waker>, waker: &Waker) {
    if !wakers.iter().any(|kept| kept.will_wake(waker)) {
        wakers.push(waker.clone());
    }
}

/// Wake every waker of `wakers`, which is left empty.
pub(crate) fn wake_all(wakers: &mut Vec<Waker>) {
    for waker in core::mem::take(wakers) {
        waker.wake();
    }
}

/// The cell the connection handle shares with the connection node
/// (`ConnectionHandleCell`): what the application's waits on the connection
/// read; see the [module documentation](self).
///
/// `C` is this endpoint's reason for closing, `F` the facts of the side's
/// handshake, `X` its exporter; `S`, `N` and `A` are what an established
/// layer's handle holds: the stream set's handle, the send strategy's
/// intake, and what the layer runs with of the handshake's selection. A
/// clone is the same cell. Every wait registers its waker under the cell's
/// lock, which takes no other lock.
#[allow(clippy::type_complexity)]
pub struct ConnectionHandleCell<C, F, X, S, N, A> {
    shared: Arc<Mutex<CellState<C, F, X, S, N, A>>>,
}

/// What the cell holds.
struct CellState<C, F, X, S, N, A> {
    handshake: HandshakeProgress<F, X>,
    next: NextLayer<S, N, A>,
    early: EarlyLayer<EstablishedLayerHandle<S, N, A, C>>,
    /// The handle of the latest established layer, kept after it ended.
    layer: Option<EstablishedLayerHandle<S, N, A, C>>,
    /// The reason the connection closed for, once the record has one.
    closed: Option<CloseReason<C>>,
    wakers: Vec<Waker>,
}

impl<C, F, X, S, N, A> CellState<C, F, X, S, N, A> {
    /// Give `layer` from now on: as the layer before the handshake completed
    /// when it has not, and as the latest layer.
    fn give_layer(&mut self, layer: EstablishedLayerHandle<S, N, A, C>)
    where
        S: Clone,
        N: Clone,
    {
        if matches!(self.early, EarlyLayer::Undecided) {
            self.early = match self.handshake {
                HandshakeProgress::Pending => EarlyLayer::Present(layer.clone()),
                HandshakeProgress::Completed { .. } => EarlyLayer::Absent,
            };
        }
        self.layer = Some(layer);
    }
}

/// How far the handshake got.
enum HandshakeProgress<F, X> {
    /// Not completed.
    Pending,
    /// Completed with these facts; the exporter until the connection
    /// closes.
    Completed { facts: F, exporter: Option<Arc<X>> },
}

/// What the cell has of the next established layer until it has both the
/// layer's selection and the layer: its handle is made once both came, in
/// whichever order.
enum NextLayer<S, N, A> {
    /// Neither came.
    Waiting,
    /// The handshake selected what the layer runs with.
    Selected(A),
    /// The layer was built, with its stream set's handle and the intake.
    Built { streams: S, intake: N },
}

/// Whether the connection had an established layer before its handshake
/// completed.
enum EarlyLayer<Y> {
    /// Not settled yet.
    Undecided,
    /// It had none.
    Absent,
    /// It had this one.
    Present(Y),
}

impl<C, F, X, S, N, A> ConnectionHandleCell<C, F, X, S, N, A> {
    /// A cell of a connection where nothing has happened yet.
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(CellState {
                handshake: HandshakeProgress::Pending,
                next: NextLayer::Waiting,
                early: EarlyLayer::Undecided,
                layer: None,
                closed: None,
                wakers: Vec::new(),
            })),
        }
    }

    fn state(&self) -> MutexGuard<'_, CellState<C, F, X, S, N, A>> {
        lock(&self.shared)
    }

    /// Change the state with `change`, and wake every waiter.
    fn change(&self, change: impl FnOnce(&mut CellState<C, F, X, S, N, A>)) {
        let mut state = self.state();
        change(&mut state);
        wake_all(&mut state.wakers);
    }

    /// `Ready` with what `look` finds, or `Pending` with the waker of `cx`
    /// kept until the cell changes.
    fn poll_with<R>(
        &self,
        cx: &mut Context<'_>,
        look: impl FnOnce(&CellState<C, F, X, S, N, A>) -> Option<R>,
    ) -> Poll<R> {
        let mut state = self.state();
        match look(&state) {
            Some(found) => Poll::Ready(found),
            None => {
                keep_waker(&mut state.wakers, cx.waker());
                Poll::Pending
            }
        }
    }

    // ---- what the connection writes ----

    /// The connection closed for `reason`, the first one in its record: the
    /// cell lets its exporter go. Only the first reason is kept.
    pub(crate) fn connection_closed(&self, reason: CloseReason<C>) {
        self.change(|state| {
            if state.closed.is_some() {
                return;
            }
            state.closed = Some(reason);
            if let HandshakeProgress::Completed { exporter, .. } = &mut state.handshake {
                *exporter = None;
            }
        });
    }

    /// Whether the cell has the reason the connection closed for.
    pub(crate) fn is_closed(&self) -> bool {
        self.state().closed.is_some()
    }

    /// The hello this side sends first is written, and this side has no
    /// established layer before its handshake completes: a client that
    /// sends no 0-RTT.
    pub(crate) fn no_early_layer(&self) {
        self.change(|state| {
            if matches!(state.early, EarlyLayer::Undecided) {
                state.early = EarlyLayer::Absent;
            }
        });
    }

    /// The next established layer runs with `selection` of the handshake's
    /// selection.
    pub(crate) fn keep_selection(&self, selection: A)
    where
        S: Clone,
        N: Clone,
    {
        self.change(
            |state| match core::mem::replace(&mut state.next, NextLayer::Waiting) {
                NextLayer::Waiting | NextLayer::Selected(_) => {
                    state.next = NextLayer::Selected(selection);
                }
                NextLayer::Built { streams, intake } => {
                    state.give_layer(EstablishedLayerHandle::new(streams, intake, selection));
                }
            },
        );
    }

    /// The handshake completed with `facts` and the connection's exporter,
    /// `None` when the connection let it go already. A connection that
    /// closed already does not keep the exporter.
    pub(crate) fn handshake_completed(&self, facts: F, exporter: Option<Arc<X>>) {
        self.change(|state| {
            if matches!(state.handshake, HandshakeProgress::Completed { .. }) {
                return;
            }
            let exporter = exporter.filter(|_| state.closed.is_none());
            state.handshake = HandshakeProgress::Completed { facts, exporter };
        });
    }

    /// An established layer was built, with the stream set's handle
    /// `streams` and the intake `intake`: its handle is given from now on,
    /// once the handshake selected what it runs with, as the handle of the
    /// layer before the handshake completed when it has not.
    pub(crate) fn layer_built(&self, streams: S, intake: N)
    where
        S: Clone,
        N: Clone,
    {
        self.change(
            |state| match core::mem::replace(&mut state.next, NextLayer::Waiting) {
                NextLayer::Selected(selection) => {
                    state.give_layer(EstablishedLayerHandle::new(streams, intake, selection));
                }
                NextLayer::Waiting | NextLayer::Built { .. } => {
                    state.next = NextLayer::Built { streams, intake };
                }
            },
        );
    }

    /// The latest established layer ended as `end`; only its first end is
    /// kept.
    pub(crate) fn layer_ended(&self, end: LayerEnd<C>) {
        let layer = self.state().layer.as_ref().map(|layer| layer.share());
        if let Some(layer) = layer {
            layer.end(end);
        }
    }

    // ---- what the application waits for ----

    fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<CloseReason<C>> {
        self.poll_with(cx, |state| state.closed.clone())
    }

    fn poll_handshake_completed(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<F, ConnectionClosedError<C>>>
    where
        F: Clone,
    {
        self.poll_with(cx, |state| match (&state.handshake, &state.closed) {
            (HandshakeProgress::Completed { facts, .. }, _) => Some(Ok(facts.clone())),
            (HandshakeProgress::Pending, Some(reason)) => {
                Some(Err(ConnectionClosedError::new(reason.clone())))
            }
            (HandshakeProgress::Pending, None) => None,
        })
    }

    fn poll_exporter(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Arc<X>>, ConnectionClosedError<C>>> {
        self.poll_with(cx, |state| match (&state.handshake, &state.closed) {
            (HandshakeProgress::Completed { exporter, .. }, _) => Some(Ok(exporter.clone())),
            (HandshakeProgress::Pending, Some(reason)) => {
                Some(Err(ConnectionClosedError::new(reason.clone())))
            }
            (HandshakeProgress::Pending, None) => None,
        })
    }

    #[allow(clippy::type_complexity)]
    fn poll_early(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<EstablishedLayerHandle<S, N, A, C>>, ConnectionClosedError<C>>>
    where
        S: Clone,
        N: Clone,
    {
        self.poll_with(cx, |state| match (&state.early, &state.closed) {
            (EarlyLayer::Present(layer), _) => Some(Ok(Some(layer.clone()))),
            (EarlyLayer::Absent, _) => Some(Ok(None)),
            (EarlyLayer::Undecided, Some(reason)) => {
                Some(Err(ConnectionClosedError::new(reason.clone())))
            }
            (EarlyLayer::Undecided, None) => None,
        })
    }

    #[allow(clippy::type_complexity)]
    fn poll_established(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<EstablishedLayerHandle<S, N, A, C>, ConnectionClosedError<C>>>
    where
        S: Clone,
        N: Clone,
    {
        self.poll_with(cx, |state| {
            match (&state.handshake, &state.layer, &state.closed) {
                (HandshakeProgress::Completed { .. }, Some(layer), _) => Some(Ok(layer.clone())),
                // a handshake that completed without its layer, or did not
                // complete, before the connection closed
                (_, _, Some(reason)) => Some(Err(ConnectionClosedError::new(reason.clone()))),
                (HandshakeProgress::Pending, _, None) | (_, None, None) => None,
            }
        })
    }
}

/// A clone is the same cell.
impl<C, F, X, S, N, A> Clone for ConnectionHandleCell<C, F, X, S, N, A> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<C, F, X, S, N, A> Default for ConnectionHandleCell<C, F, X, S, N, A> {
    fn default() -> Self {
        Self::new()
    }
}

/// It shows how far the connection got, not what the cell holds.
impl<C, F, X, S, N, A> fmt::Debug for ConnectionHandleCell<C, F, X, S, N, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state();
        f.debug_struct("ConnectionHandleCell")
            .field(
                "handshake_completed",
                &matches!(state.handshake, HandshakeProgress::Completed { .. }),
            )
            .field("layer", &state.layer.is_some())
            .field("closed", &state.closed.is_some())
            .finish_non_exhaustive()
    }
}

// ---- the types of the choices ----

/// The facts of the handshake of the side of the choices `T`.
pub type HandshakeFactsOf<T> = <<T as Choices>::Side as Side>::HandshakeFacts;

/// What an established layer of the choices `T` runs with of the
/// handshake's selection.
pub type LayerSelectionOf<T> = <<T as Choices>::Side as Side>::LayerSelection;

/// The handle the stream set of the choices `T` and the list of parts `L`
/// gives the application.
pub type StreamSetHandleOf<T, L> =
    <StreamsOf<T, L> as StreamSet<CloseCauseOf<T, L>, StreamIntentTicketOf<T, L>>>::Handle;

/// The cell of the connection handle of the choices `T` and the list of
/// parts `L`.
pub type ConnectionHandleCellOf<T, L> = ConnectionHandleCell<
    CloseCauseOf<T, L>,
    HandshakeFactsOf<T>,
    <<T as Choices>::Side as Side>::Exporter,
    StreamSetHandleOf<T, L>,
    IntakeOf<T, L>,
    LayerSelectionOf<T>,
>;

/// The handle of an established layer of the choices `T` and the list of
/// parts `L`.
pub type EstablishedLayerHandleOf<T, L> = EstablishedLayerHandle<
    StreamSetHandleOf<T, L>,
    IntakeOf<T, L>,
    LayerSelectionOf<T>,
    CloseCauseOf<T, L>,
>;

/// Where [`ConnectionArgs`] holds the cell of the connection handle of the
/// choices `T` and the list of parts `L` (`ConnectionHandleCellSlot`): the
/// connection node takes its clone of the cell from it when it is built,
/// and [`ConnectionHandle::new`] another. A clone is the same slot.
///
/// The cell's type ([`ConnectionHandleCellOf`]) needs the connection's
/// errors, send strategy and intake of stream intents, which a field of
/// `ConnectionArgs` could name only under bounds that whoever makes
/// `ConnectionArgs` would repeat. The slot names only `T` and `L`: it makes
/// the cell on first use and keeps it behind `dyn Any`, an erasure boundary
/// of this one value. What it keeps is always the cell of its own `T` and
/// `L`, so taking it back never fails.
pub struct ConnectionHandleCellSlot<T, L> {
    cell: Arc<OnceLock<Box<dyn Any + Send + Sync>>>,
    types: PhantomData<fn() -> (T, L)>,
}

impl<T, L> ConnectionHandleCellSlot<T, L> {
    /// A slot whose cell is not made yet.
    pub fn new() -> Self {
        Self {
            cell: Arc::new(OnceLock::new()),
            types: PhantomData,
        }
    }
}

impl<T, L> ConnectionHandleCellSlot<T, L>
where
    T: Choices,
    L: ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    ConnectionHandleCellOf<T, L>: Send + Sync + 'static,
{
    /// A clone of the cell, made now if it was not.
    pub(crate) fn cell(&self) -> ConnectionHandleCellOf<T, L> {
        let kept = self
            .cell
            .get_or_init(|| Box::new(ConnectionHandleCellOf::<T, L>::new()));
        // invariant: only this method fills the slot, with the cell of the
        // slot's own `T` and `L`, and a slot's clones keep its types
        match kept.downcast_ref::<ConnectionHandleCellOf<T, L>>() {
            Some(cell) => cell.clone(),
            None => unreachable!("a slot keeps the cell of its own types"),
        }
    }
}

/// A clone is the same slot.
impl<T, L> Clone for ConnectionHandleCellSlot<T, L> {
    fn clone(&self) -> Self {
        Self {
            cell: Arc::clone(&self.cell),
            types: PhantomData,
        }
    }
}

impl<T, L> Default for ConnectionHandleCellSlot<T, L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, L> fmt::Debug for ConnectionHandleCellSlot<T, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionHandleCellSlot")
            .field("made", &self.cell.get().is_some())
            .finish()
    }
}

// ---- the cell in the connection node ----

/// The record of why the connection closed and the cell are made
/// together: no connection starts closing, and the connection node keeps a
/// clone of the cell of the slot the connection was made with.
///
/// When the connection node ends, the cell takes the record's reason. A
/// connection that ends at once where its reason is written, as at the
/// idle timeout, ends before the cell is read again; without this end the
/// cell would never learn the reason, and every wait on it would wait
/// forever.
impl<T, L, I> Build<T, L, layer::Connection, (I,)>
    for frunk_core::HList![
        CloseReasonRecord<CloseCauseOf<T, L>>,
        ConnectionHandleCellOf<T, L>
    ]
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    ConnectionHandleCellOf<T, L>: Send + Sync + 'static,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        let cell = Selector::<ConnectionArgs<T, L>, I>::get_mut(args)
            .connection_handle
            .cell();
        frunk_core::hlist![CloseReasonRecord::new(), cell]
    }

    fn end<'v, B: CallBundle>(
        self,
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
    ) {
        let frunk_core::hlist_pat![record, cell] = self;
        match record.reason() {
            Some(reason) => cell.connection_closed(reason.clone()),
            // invariant: the connection ends where its reason is written, or
            // once the record that has one asks for it, and a dropped future
            // writes it before any node ends
            None => debug_assert!(false, "the connection ends without a reason"),
        }
    }
}

/// The cell reads the record of why the connection closed and takes its
/// reason once it is written. When the connection's future is dropped it
/// takes the reason the record has then, or [`CloseReason::Aborted`] with
/// the cause; after a panic, which runs no end action, it also ends the
/// layer whose handle it gives.
impl<T, L, I, Ic> DataComponent<T, L, layer::Connection, (I, Ic)> for ConnectionHandleCellOf<T, L>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<Self, I> + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>,
{
    fn reads(reads: &mut ReadSet) {
        reads.add::<CloseReasonRecord<CloseCauseOf<T, L>>>();
    }

    fn reread<'v, B: CallBundle>(
        lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let cell = lineage.get::<Self, I>();
        if !cell.is_closed()
            && let Some(reason) = lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .reason()
        {
            cell.connection_closed(reason.clone());
        }
        None
    }

    fn future_dropped<'v>(lineage: &mut LineageOf<'v, T, L, layer::Connection>, cause: AbortCause) {
        let reason = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .reason()
            .cloned()
            .unwrap_or(CloseReason::Aborted(cause));
        let cell = lineage.get::<Self, I>();
        cell.connection_closed(reason.clone());
        if cause == AbortCause::Panicked {
            cell.layer_ended(LayerEnd::ConnectionClosed(reason));
        }
    }
}

// ---- the connection handle ----

/// The handle of a connection in the application's hands
/// (`ConnectionHandle`): it asks for the close, and waits for the reason,
/// the handshake's result and the handles of the established layers.
///
/// `T` is the composition's choices, `L` its list of parts. A clone is the
/// same handle; dropping every handle does not close the connection. The
/// futures of the waits borrow the handle and nothing else, and every task
/// that waits gets the same result.
pub struct ConnectionHandle<T, L>
where
    T: Choices,
    L: ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
{
    cell: ConnectionHandleCellOf<T, L>,
    close_request: CloseRequestCell<T::ApplicationError>,
}

impl<T, L> ConnectionHandle<T, L>
where
    T: Choices,
    L: LogicalPathKeys + ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    ConnectionHandleCellOf<T, L>: Send + Sync + 'static,
{
    /// The handle of the connection made with `args`, sharing the cells it
    /// holds: what an endpoint gives the application when it makes a
    /// connection, and what tests that make a connection themselves use.
    pub fn new(args: &ConnectionArgs<T, L>) -> Self {
        Self {
            cell: args.connection_handle.cell(),
            close_request: args.close_request.clone(),
        }
    }
}

impl<T, L> ConnectionHandle<T, L>
where
    T: Choices,
    L: ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
{
    /// Ask to close the connection with `error`; the connection takes the
    /// request at its next poll. It does not wait for data to be sent, and
    /// tells nothing of which reason is first: that is [`closed`]'s. Only
    /// the first request counts.
    ///
    /// [`closed`]: Self::closed
    pub fn close(&self, error: T::ApplicationError) {
        self.close_request.request(error);
    }

    /// The reason the connection closed for, once it did: the first in its
    /// record, the same for every caller.
    pub fn closed(&self) -> impl Future<Output = CloseReason<CloseCauseOf<T, L>>> + '_ {
        poll_fn(|cx| self.cell.poll_closed(cx))
    }

    /// The facts of the handshake, once it completed; also after the
    /// connection closed.
    ///
    /// # Errors
    ///
    /// [`ConnectionClosedError`] when the connection closed before the
    /// handshake completed.
    pub fn handshake_completed(
        &self,
    ) -> impl Future<Output = Result<HandshakeFactsOf<T>, ConnectionClosedError<CloseCauseOf<T, L>>>> + '_
    where
        HandshakeFactsOf<T>: Clone,
    {
        poll_fn(|cx| self.cell.poll_handshake_completed(cx))
    }

    /// The handle of the established layer before the handshake completed,
    /// once it is settled whether there is one: `None` when the connection
    /// never had one, `Some` when it had, also once the handshake completed.
    /// A server has one from its ServerHello written; a client of this
    /// version never has, as it sends no 0-RTT.
    ///
    /// # Errors
    ///
    /// [`ConnectionClosedError`] when the connection closed before it was
    /// settled.
    #[allow(clippy::type_complexity)]
    pub fn early(
        &self,
    ) -> impl Future<
        Output = Result<
            Option<EstablishedLayerHandleOf<T, L>>,
            ConnectionClosedError<CloseCauseOf<T, L>>,
        >,
    > + '_
    where
        StreamSetHandleOf<T, L>: Clone,
    {
        poll_fn(|cx| self.cell.poll_early(cx))
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
    pub fn established(
        &self,
    ) -> impl Future<
        Output = Result<EstablishedLayerHandleOf<T, L>, ConnectionClosedError<CloseCauseOf<T, L>>>,
    > + '_
    where
        StreamSetHandleOf<T, L>: Clone,
    {
        poll_fn(|cx| self.cell.poll_established(cx))
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
    pub fn exporter(
        &self,
    ) -> impl Future<
        Output = Result<
            Option<Arc<<T::Side as Side>::Exporter>>,
            ConnectionClosedError<CloseCauseOf<T, L>>,
        >,
    > + '_ {
        poll_fn(|cx| self.cell.poll_exporter(cx))
    }
}

/// A clone is the same handle.
impl<T, L> Clone for ConnectionHandle<T, L>
where
    T: Choices,
    L: ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
{
    fn clone(&self) -> Self {
        Self {
            cell: self.cell.clone(),
            close_request: self.close_request.clone(),
        }
    }
}

impl<T, L> fmt::Debug for ConnectionHandle<T, L>
where
    T: Choices,
    L: ConnectionErrorsOf,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<T::SendParameters>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionHandle").finish_non_exhaustive()
    }
}

/// The share of a layer the cell gives the handle of.
impl<S, N, A, C> EstablishedLayerHandle<S, N, A, C> {
    fn share(&self) -> Arc<LayerShare<A, C>> {
        Arc::clone(&self.layer)
    }
}
