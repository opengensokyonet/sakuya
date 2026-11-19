//! The default queues of the established layer: one lock over both bounded
//! queues, which the connection and the application's handles share
//! ([`LockedDatagramQueues`]).
//!
//! - **Receiving.** A datagram received waits until the application reads
//!   it; the queue holds at most so many datagrams and so many bytes of
//!   payload ([`DatagramQueueBounds`]). When one more comes, the queue
//!   drops the oldest ones or the new one, as it is configured
//!   ([`DatagramOverflow`]), and counts what it dropped
//!   ([`EstablishedLayerHandle::dropped_datagrams`]). Receiving never
//!   waits for the application (RFC 9221 §5). The bytes are counted by
//!   payload: a datagram may keep the buffer of its whole packet.
//! - **Sending.** A datagram waits in the send queue from when it is sent
//!   until it is written into a packet or withdrawn; the queue's bounds are
//!   counted over those waiting. When one more is sent, the queue refuses it
//!   or withdraws the oldest ones to make room, as it is configured. A
//!   datagram whose ticket was released stays in the queue until it is
//!   written, so the strategy's ticket stays with it.
//! - **The end of the layer.** What was received is still read; then
//!   every read reports the end, and so does every send. The datagrams
//!   still waiting are withdrawn.
//! - **A panic of the driver.** The end is only marked
//!   ([`DatagramQueues::driver_panicked`]): who waits to receive and the tickets of
//!   the datagrams in the send queue are woken; every receive and send then
//!   reports the end at once, also before what was received, and those
//!   tickets settle as withdrawn as the layer ended; the tickets of the
//!   datagrams in flight are woken too and settle as lost. Nothing is withdrawn
//!   and the strategy's tickets are left alone.
//!
//! Lock order: the queues' lock comes first; a datagram's progress and its
//! route are taken under it, one at a time, and publishing or withdrawing an
//! intent takes the send strategy's lock under it. The DATAGRAM frame
//! source takes no lock of the queues: it writes from the intent, and the
//! queue counts a datagram written as gone the next time it looks. The
//! events of the datagrams are given under the queues' lock.

use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    fmt,
    future::{Future, poll_fn},
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
};
use std::sync::{Mutex, OnceLock};

use bytes::{Buf, Bytes};
use sakuya_stream::{
    connection::{LayerEnd, LayerEndedError},
    send_options::{
        NoSendOptions,
        destination::{AnyActiveLinkPath, SendDestination},
        urgency::Urgency,
    },
};
use sakuya_wire::{
    datagram::DatagramFrame, parts::Selector, v1::encryption_level::EncryptionLevel,
};

use super::{
    DatagramChoices, DatagramIntentHandleOf, DatagramOverflow, DatagramQueues, DatagramQueuesFacts,
    DatagramQueuesOf, DatagramSide, DatagramTicketOf,
    application::{
        DatagramFrameLimits, DatagramSend, DatagramWriter, Datagrams, SendDatagramError,
    },
    frame_len_with_length, lock, payload_limit,
    send::{
        DatagramCell, DatagramIntent, DatagramProgress, DatagramTicket, DatagramWithdrawCause,
        DriverPanicFlag, Withdrawal,
    },
};
use crate::{
    component::LineageOf,
    driver::LendNode,
    error::ConnectionErrorsOf,
    layer,
    send_strategy::{
        IntentTicketWithdraw, PublishOutcome, SendIntentHandle, SendIntentIntake, SharedPublishTo,
    },
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::GetAt,
    v1::{
        Choices, CloseCauseOf,
        application_handles::{
            connection::{
                ConnectionHandleRemainsOf, ConnectionHandleStateOf, keep_waker, wake_all,
            },
            established_layer::EstablishedLayerHandle,
        },
        events::{DataLocation, DatagramDropped, NoEvents, SharedEvents},
        send::SendTypes,
        send_planning::{
            HostSendStrategyTypes, IntakeOf, IntakePublishOutcome, SendStrategyIntake,
        },
    },
};

/// The bounds of one queue of datagrams (`DatagramQueueBounds`): how many
/// datagrams and how many bytes of payload it holds at most, and what it
/// does when one more comes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramQueueBounds {
    /// How many datagrams it holds at most.
    pub datagrams: NonZeroUsize,
    /// How many bytes of payload it holds at most.
    pub bytes: usize,
    /// What it does when one more comes.
    pub overflow: DatagramOverflow,
}

/// 64 datagrams, 64 KiB of payload, and the new one refused.
impl Default for DatagramQueueBounds {
    fn default() -> Self {
        Self {
            datagrams: NonZeroUsize::new(64).expect("not zero"),
            bytes: 64 * 1024,
            overflow: DatagramOverflow::default(),
        }
    }
}

/// What [`LockedDatagramQueues`] is configured with
/// (`LockedDatagramQueuesConfig`): the bounds of each queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LockedDatagramQueuesConfig {
    /// The bounds of the datagrams received.
    pub receive: DatagramQueueBounds,
    /// The bounds of the datagrams waiting to be sent.
    pub send: DatagramQueueBounds,
}

/// The queues of one established layer, under one lock the connection and
/// the application's handles share (`LockedDatagramQueues`).
///
/// `Lc` is this endpoint's reason for closing, `K` the ticket the send
/// strategy gives back for a datagram's intent, `S` the side, which gives
/// what a datagram received is, and `E` the handle the events of the
/// datagrams are given through, by default [`NoEvents`]: a datagram the
/// send queue takes and one a read gives the application move between the
/// application and the transport, and each one a queue drops for its bounds
/// is dropped ([`SharedEvents`]); each is given under the queues' lock.
/// Datagrams are sent with an [`Urgency`], to any active link path.
pub struct LockedDatagramQueues<Lc, K, S: DatagramSide, E = NoEvents> {
    shared: Arc<QueuesShare<Lc, K, S, E>>,
}

/// The default queues of the established layer.
pub type DefaultDatagramQueues<Lc, K, S, E = NoEvents> = LockedDatagramQueues<Lc, K, S, E>;

/// A datagram to send, as the send queue holds it.
type SendCell<K> = DatagramCell<K, AnyActiveLinkPath, Urgency>;

/// What the queues and their handles share.
struct QueuesShare<Lc, K, S: DatagramSide, E> {
    /// The largest payload the peer takes; `None` when it takes no
    /// DATAGRAM frames.
    peer_limit: Option<usize>,
    /// The peer's `max_datagram_frame_size`, counted as a frame length.
    peer_frame_limit: usize,
    config: LockedDatagramQueuesConfig,
    /// How the layer ended, once the driver panicked: only marked, with
    /// the queues left as the panic left them. Every receive and send looks
    /// at it first, under the queues' lock.
    panic_end: OnceLock<LayerEnd<Lc>>,
    /// Whether the driver panicked, as the cells of the datagrams sent
    /// read it.
    panicked: Arc<DriverPanicFlag>,
    state: Mutex<QueuesState<Lc, K, S::Received>>,
    /// The handle the events of the datagrams are given through.
    events: E,
}

struct QueuesState<Lc, K, R> {
    received: VecDeque<R>,
    received_bytes: usize,
    dropped: u64,
    /// Who waits for a datagram received.
    receivers: Vec<Waker>,
    waiting: VecDeque<Arc<SendCell<K>>>,
    waiting_bytes: usize,
    /// The datagrams that left the send queue written into a packet whose
    /// fate is not known yet, while their tickets are held: what a panic of
    /// the driver wakes the tickets of. Those settled or let go leave it
    /// each time the send queue is resolved.
    in_flight: Vec<Weak<SendCell<K>>>,
    /// How the layer ended, once it did.
    end: Option<LayerEnd<Lc>>,
}

impl<Lc, K, S: DatagramSide, E> fmt::Debug for LockedDatagramQueues<Lc, K, S, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedDatagramQueues")
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

impl<Lc, K: IntentTicketWithdraw, S: DatagramSide, E: SharedEvents> QueuesShare<Lc, K, S, E> {
    /// A datagram of `level` and `frame` arrived: kept, or dropped as the
    /// receive queue's bounds say.
    fn receive(&self, level: EncryptionLevel, frame: DatagramFrame<Bytes>) {
        let bounds = self.config.receive;
        let datagram = S::received(level, frame.into_data());
        let len = datagram.remaining();
        let mut state = lock(&self.state);
        if state.end.is_some() {
            return;
        }
        if len > bounds.bytes {
            // larger than the whole queue: dropped, the others kept
            state.dropped += 1;
            self.dropped(len, DatagramDropped::ReceiveQueueFull);
            return;
        }
        let fits = |state: &QueuesState<Lc, K, S::Received>| {
            state.received.len() < bounds.datagrams.get()
                && state.received_bytes.saturating_add(len) <= bounds.bytes
        };
        while !fits(&state) {
            let oldest = match bounds.overflow {
                DatagramOverflow::DropOldest => state.received.pop_front(),
                DatagramOverflow::RejectNew => None,
            };
            let Some(oldest) = oldest else {
                // the new one is dropped
                state.dropped += 1;
                self.dropped(len, DatagramDropped::ReceiveQueueFull);
                return;
            };
            state.received_bytes -= oldest.remaining();
            state.dropped += 1;
            self.dropped(oldest.remaining(), DatagramDropped::ReceiveQueueFull);
        }
        state.received_bytes += len;
        state.received.push_back(datagram);
        wake_all(&mut state.receivers);
    }

    /// The next datagram received, or the layer's end once none is left.
    fn poll_receive(&self, cx: &mut Context<'_>) -> Poll<Result<S::Received, LayerEndedError<Lc>>> {
        let mut state = lock(&self.state);
        if let Some(end) = self.panic_end.get() {
            return Poll::Ready(Err(LayerEndedError::new(end.clone())));
        }
        if let Some(datagram) = state.received.pop_front() {
            state.received_bytes -= datagram.remaining();
            if let Some(events) = self.events() {
                let len = datagram.remaining();
                events.datagram_data_moved(len, DataLocation::Transport, DataLocation::Application);
            }
            return Poll::Ready(Ok(datagram));
        }
        match &state.end {
            Some(end) => Poll::Ready(Err(LayerEndedError::new(end.clone()))),
            None => {
                keep_waker(&mut state.receivers, cx.waker());
                Poll::Pending
            }
        }
    }

    /// The layer ended as `end`: the waiting datagrams are withdrawn, and
    /// who waits for one received hears of it.
    fn end(&self, end: LayerEnd<Lc>) {
        let mut state = lock(&self.state);
        if state.end.is_some() {
            return;
        }
        state.end = Some(end);
        wake_all(&mut state.receivers);
        state.waiting_bytes = 0;
        for cell in core::mem::take(&mut state.waiting) {
            cell.withdraw(Withdrawal::Cause(DatagramWithdrawCause::LayerEnded));
        }
    }

    /// Take `payload` into the send queue, publishing its intent through
    /// `publish`, with `parameters`, to `destination`.
    fn send<H>(
        &self,
        publish: &H,
        payload: Bytes,
        parameters: Urgency,
        destination: AnyActiveLinkPath,
    ) -> Result<DatagramTicket<K, AnyActiveLinkPath, Urgency>, SendDatagramError<Lc>>
    where
        H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    {
        let Some(limit) = self.peer_limit else {
            return Err(SendDatagramError::NotSupportedByPeer);
        };
        let len = payload.len();
        if frame_len_with_length(len) > self.peer_frame_limit {
            return Err(SendDatagramError::TooLarge { limit });
        }
        let bounds = self.config.send;
        let mut state = lock(&self.state);
        if let Some(end) = self.panic_end.get().or(state.end.as_ref()) {
            return Err(LayerEndedError::new(end.clone()).into());
        }
        if len > bounds.bytes {
            // larger than the whole queue: no room can be made for it
            return Err(SendDatagramError::QueueFull);
        }
        Self::resolve_waiting(&mut state, publish);
        let fits = |state: &QueuesState<Lc, K, S::Received>| {
            state.waiting.len() < bounds.datagrams.get()
                && state.waiting_bytes.saturating_add(len) <= bounds.bytes
        };
        while !fits(&state) {
            let oldest = match bounds.overflow {
                DatagramOverflow::DropOldest => state.waiting.pop_front(),
                DatagramOverflow::RejectNew => None,
            };
            let Some(oldest) = oldest else {
                return Err(SendDatagramError::QueueFull);
            };
            state.waiting_bytes -= oldest.len();
            self.dropped(oldest.len(), DatagramDropped::SendQueueFull);
            // written meanwhile, it leaves the queue all the same
            oldest.withdraw(Withdrawal::Cause(DatagramWithdrawCause::DroppedOldest));
        }
        let progress = DatagramProgress::new();
        let intent = DatagramIntent::new(payload, parameters, progress);
        let ticket = publish.publish_to(intent.clone(), destination.current());
        let cell = DatagramCell::new(intent, ticket, destination, Arc::clone(&self.panicked));
        state.waiting_bytes += len;
        state.waiting.push_back(Arc::clone(&cell));
        if let Some(events) = self.events() {
            events.datagram_data_moved(len, DataLocation::Application, DataLocation::Transport);
        }
        Ok(DatagramTicket::new(cell))
    }

    /// What was written or withdrawn since leaves the send queue of
    /// `state`; what was not fulfilled goes on as its destination says,
    /// published again through `publish` or withdrawn.
    fn resolve_waiting<H>(state: &mut QueuesState<Lc, K, S::Received>, publish: &H)
    where
        H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    {
        state
            .in_flight
            .retain(|cell| cell.upgrade().is_some_and(|cell| cell.is_in_flight()));
        let mut gone = 0;
        let mut sent = Vec::new();
        state.waiting.retain(|cell| {
            cell.resolve_unfulfilled(publish);
            let waiting = cell.is_waiting();
            if !waiting {
                gone += cell.len();
                if cell.is_in_flight() {
                    sent.push(Arc::downgrade(cell));
                }
            }
            waiting
        });
        state.waiting_bytes -= gone;
        state.in_flight.extend(sent);
    }

    /// The handle for the events of the datagrams, when they are recorded.
    #[inline(always)]
    fn events(&self) -> Option<&E> {
        (E::ENABLED && self.events.enabled()).then_some(&self.events)
    }

    /// A datagram of `length` bytes of payload was dropped as `dropped`
    /// says; under the queues' lock.
    fn dropped(&self, length: usize, dropped: DatagramDropped) {
        if let Some(events) = self.events() {
            events.datagram_dropped(length, dropped);
        }
    }

    fn limits(&self) -> DatagramFrameLimits {
        let limit = self.peer_limit.unwrap_or(0);
        DatagramFrameLimits {
            everywhere: limit,
            somewhere: limit,
        }
    }
}

/// The kind of [`LockedDatagramQueues`].
#[derive(Debug)]
pub struct LockedDatagramQueuesFamily;

impl super::DatagramQueuesFamily for LockedDatagramQueuesFamily {
    type Config = LockedDatagramQueuesConfig;
    type Queues<Lc, K: IntentTicketWithdraw, S: DatagramSide, E: SharedEvents + Clone + 'static> =
        LockedDatagramQueues<Lc, K, S, E>;
}

impl<Lc, K, S, E> DatagramQueues<Lc> for LockedDatagramQueues<Lc, K, S, E>
where
    K: IntentTicketWithdraw,
    S: DatagramSide,
    E: SharedEvents,
{
    type Config = LockedDatagramQueuesConfig;
    type Handle = LockedDatagramQueuesHandle<Lc, K, S, E>;
    type StrategyTicket = K;
    type Events = E;

    fn new(facts: DatagramQueuesFacts, config: LockedDatagramQueuesConfig, events: E) -> Self {
        let peer_frame_limit = usize::try_from(facts.peer.get().get()).unwrap_or(usize::MAX);
        let peer_limit = (peer_frame_limit > 0).then(|| payload_limit(facts.peer).unwrap_or(0));
        Self {
            shared: Arc::new(QueuesShare {
                peer_limit,
                peer_frame_limit,
                config,
                panic_end: OnceLock::new(),
                panicked: Arc::default(),
                state: Mutex::new(QueuesState {
                    received: VecDeque::new(),
                    received_bytes: 0,
                    dropped: 0,
                    receivers: Vec::new(),
                    waiting: VecDeque::new(),
                    waiting_bytes: 0,
                    in_flight: Vec::new(),
                    end: None,
                }),
                events,
            }),
        }
    }

    fn handle(&self) -> LockedDatagramQueuesHandle<Lc, K, S, E> {
        LockedDatagramQueuesHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    fn on_datagram_frame(&mut self, level: EncryptionLevel, frame: DatagramFrame<Bytes>) {
        self.shared.receive(level, frame);
    }

    fn layer_ended(&mut self, end: LayerEnd<Lc>) {
        self.shared.end(end);
    }

    /// The end is marked in what the queues share with their handles, and
    /// who waits is woken; nothing is withdrawn.
    fn driver_panicked(&mut self, end: LayerEnd<Lc>) {
        self.shared.driver_panicked(end);
    }

    fn resolve_unfulfilled<H>(&mut self, publish: &H)
    where
        H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    {
        QueuesShare::<Lc, K, S, E>::resolve_waiting(&mut lock(&self.shared.state), publish);
    }
}

/// The handle of a [`LockedDatagramQueues`] (`LockedDatagramQueuesHandle`):
/// it shares the queues' state. The capability of the established layer's
/// handle takes it from the queues it is lent. A clone is the same handle.
pub struct LockedDatagramQueuesHandle<Lc, K, S: DatagramSide, E = NoEvents> {
    shared: Arc<QueuesShare<Lc, K, S, E>>,
}

impl<Lc, K, S: DatagramSide, E> Clone for LockedDatagramQueuesHandle<Lc, K, S, E> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<Lc, K, S: DatagramSide, E> QueuesShare<Lc, K, S, E> {
    /// The driver panicked: mark the end in what the queues share with
    /// their handles and wake who waits to receive and who waits for a
    /// datagram in the send queue, or one in flight, to settle; nothing is
    /// withdrawn.
    fn driver_panicked(&self, end: LayerEnd<Lc>) {
        let shared = self;
        if shared.panic_end.set(end).is_err() {
            return;
        }
        shared.panicked.set();
        let waiting = {
            let mut state = lock(&shared.state);
            wake_all(&mut state.receivers);
            let in_flight = state.in_flight.iter().filter_map(Weak::upgrade);
            state
                .waiting
                .iter()
                .cloned()
                .chain(in_flight)
                .collect::<Vec<_>>()
        };
        for cell in waiting {
            cell.wake_settled_waiters();
        }
    }
}

impl<Lc, K, S: DatagramSide, E> fmt::Debug for LockedDatagramQueuesHandle<Lc, K, S, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedDatagramQueuesHandle")
            .finish_non_exhaustive()
    }
}

impl<Lc, K, S: DatagramSide, E> LockedDatagramQueuesHandle<Lc, K, S, E> {
    /// How many datagrams received were dropped because the receive queue
    /// was full; it only grows.
    pub fn dropped_datagrams(&self) -> u64 {
        lock(&self.shared.state).dropped
    }
}

/// The handle of the established layer `T`, `L`, `S`, `A` whose queues are
/// the default ones.
///
/// `K`, `D` and `E` are the queues' parameters, as their handle names
/// them. `Ie`, `Ic` and `Ir` are where the connection handle's state is in
/// the layer's lineage and in the connection node's, and where version 1's
/// part is in what the parts keep after the end; `Iq` is where the queues
/// are in the layer's lineage. The compiler infers them.
impl<T, L, S, A> EstablishedLayerHandle<T, L, S, A>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
    DatagramTicketOf<T, L>: IntentTicketWithdraw,
{
    /// Lend the layer once to `op`, with the queues' shared state and the
    /// layer's lineage; otherwise how the layer ended.
    #[allow(clippy::type_complexity)] // the queues of four type parameters
    fn with_queues<R, K, D, E, Ie, Ic, Ir, Iq>(
        &self,
        op: impl for<'v> FnOnce(
            &Arc<QueuesShare<CloseCauseOf<T, L>, K, D, E>>,
            LineageOf<'v, T, L, layer::Established>,
        ) -> R,
    ) -> Result<R, LayerEnd<CloseCauseOf<T, L>>>
    where
        D: DatagramSide,
        DatagramQueuesOf<T, L>: DatagramQueues<
                CloseCauseOf<T, L>,
                Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, E>,
            >,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established:
            GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        self.lend_layer::<_, Ie, Ic, Ir>(|lineage, _| {
            let shared = lineage.get::<DatagramQueuesOf<T, L>, Iq>().handle().shared;
            op(&shared, lineage)
        })
    }

    /// How many datagrams the layer received were dropped because the
    /// receive queue was full
    /// ([`LockedDatagramQueuesHandle::dropped_datagrams`]).
    ///
    /// # Errors
    ///
    /// [`LayerEndedError`] once the layer ended: its queues are gone with
    /// it.
    pub fn dropped_datagrams<K, D, E, Ie, Ic, Ir, Iq>(
        &self,
    ) -> Result<u64, LayerEndedError<CloseCauseOf<T, L>>>
    where
        D: DatagramSide,
        DatagramQueuesOf<T, L>: DatagramQueues<
                CloseCauseOf<T, L>,
                Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, E>,
            >,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established:
            GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        self.with_queues::<_, K, D, E, Ie, Ic, Ir, Iq>(|shared, _| lock(&shared.state).dropped)
            .map_err(LayerEndedError::new)
    }
}

/// The capability of the default queues, on the handle of an established
/// layer: each call, and each poll of a receive, lends the layer once and
/// takes the queues' handle from it. The writer publishes through the
/// intake's handle for the datagram intents at the place `I`, `In` being
/// where the intake is in the layer's lineage, and holds the queues' shared
/// state, apart from the connection; one taken once the layer ended
/// reports the end. The other places are as for the handle's
/// [`dropped_datagrams`](EstablishedLayerHandle::dropped_datagrams).
impl<T, L, S, A, K, D, E, Ie, Ic, Ir, Iq, In, I> Datagrams<(Ie, Ic, Ir, Iq, In, I)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>:
        IntakePublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath> + HostSendStrategyTypes,
    DatagramTicketOf<T, L>: IntentTicketWithdraw,
    K: IntentTicketWithdraw,
    D: DatagramSide,
    E: SharedEvents,
    DatagramQueuesOf<T, L>: DatagramQueues<
            CloseCauseOf<T, L>,
            Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, E>,
        >,
    IntakeOf<T, L>: SendIntentIntake<AnyActiveLinkPath>
        + SharedPublishTo<DatagramIntent<Urgency>, AnyActiveLinkPath, I>
        + PublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>
        + GetAt<DatagramQueuesOf<T, L>, Iq>
        + GetAt<SendStrategyIntake<IntakeOf<T, L>>, In>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
{
    type Received = D::Received;
    type SendShare =
        LockedDatagramSendShare<CloseCauseOf<T, L>, K, D, DatagramIntentHandleOf<T, L, I>, E>;
    type CloseCause = CloseCauseOf<T, L>;

    fn datagram_writer(&self) -> DatagramWriter<Self::SendShare, NoSendOptions> {
        let queue = self
            .with_queues::<_, K, D, E, Ie, Ic, Ir, Iq>(|shared, lineage| SendQueueReach::Queues {
                shared: Arc::clone(shared),
                publish: lineage
                    .get::<SendStrategyIntake<IntakeOf<T, L>>, In>()
                    .intake()
                    .handle::<DatagramIntent<Urgency>, I>(),
            })
            .unwrap_or_else(SendQueueReach::Ended);
        DatagramWriter::new(LockedDatagramSendShare { queue })
    }

    fn recv_datagram(
        &self,
    ) -> impl Future<Output = Result<D::Received, LayerEndedError<CloseCauseOf<T, L>>>> {
        poll_fn(move |cx| {
            self.with_queues::<_, K, D, E, Ie, Ic, Ir, Iq>(|shared, _| shared.poll_receive(cx))
                .unwrap_or_else(|end| Poll::Ready(Err(LayerEndedError::new(end))))
        })
    }
}

/// This side's share of the send queue of a [`LockedDatagramQueues`]
/// (`LockedDatagramSendShare`), with the handle `H` it publishes through;
/// one taken once its layer ended reports the end.
pub struct LockedDatagramSendShare<Lc, K, S: DatagramSide, H, E = NoEvents> {
    queue: SendQueueReach<Lc, K, S, H, E>,
}

/// What a share of the send queue reaches.
enum SendQueueReach<Lc, K, S: DatagramSide, H, E> {
    /// The queues' shared state, published to through `publish`.
    Queues {
        shared: Arc<QueuesShare<Lc, K, S, E>>,
        publish: H,
    },
    /// Nothing: the layer had ended when the share was taken.
    Ended(LayerEnd<Lc>),
}

impl<Lc, K, S: DatagramSide, H: Clone, E> Clone for LockedDatagramSendShare<Lc, K, S, H, E> {
    fn clone(&self) -> Self {
        let queue = match &self.queue {
            SendQueueReach::Queues { shared, publish } => SendQueueReach::Queues {
                shared: Arc::clone(shared),
                publish: publish.clone(),
            },
            SendQueueReach::Ended(end) => SendQueueReach::Ended(end.clone()),
        };
        Self { queue }
    }
}

impl<Lc, K, S: DatagramSide, H, E> fmt::Debug for LockedDatagramSendShare<Lc, K, S, H, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedDatagramSendShare")
            .finish_non_exhaustive()
    }
}

/// Datagrams are sent with an urgency, to any active link path.
impl<Lc, K, S, H, E> DatagramSend for LockedDatagramSendShare<Lc, K, S, H, E>
where
    K: IntentTicketWithdraw,
    S: DatagramSide,
    E: SharedEvents,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
{
    type Parameters = Urgency;
    type Destination = AnyActiveLinkPath;
    type CloseCause = Lc;
    type Ticket = DatagramTicket<K, AnyActiveLinkPath, Urgency>;

    fn send_with(
        &self,
        payload: Bytes,
        parameters: &Urgency,
        destination: &AnyActiveLinkPath,
    ) -> Result<Self::Ticket, SendDatagramError<Lc>> {
        match &self.queue {
            SendQueueReach::Queues { shared, publish } => {
                shared.send(publish, payload, *parameters, *destination)
            }
            SendQueueReach::Ended(end) => Err(LayerEndedError::new(end.clone()).into()),
        }
    }

    /// Nothing fits once the layer ended.
    fn datagram_limits(&self) -> DatagramFrameLimits {
        match &self.queue {
            SendQueueReach::Queues { shared, .. } => shared.limits(),
            SendQueueReach::Ended(_) => DatagramFrameLimits {
                everywhere: 0,
                somewhere: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests;
