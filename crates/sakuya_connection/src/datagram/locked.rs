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
//!   still waiting are withdrawn. What was received and not read, the count
//!   of what was dropped, and the progress of the datagrams whose tickets
//!   are held through the shared connection go into the connection node
//!   ([`LockedDatagramQueuesRemains`]), where the layer's handle and those
//!   tickets read them after the layer is gone.
//! - **Tickets.** A ticket held through the shared connection
//!   ([`SharedDatagramTicket`]) finds its datagram by a key, in a table the
//!   queues keep until the ticket's credential comes back; one held apart
//!   from the connection ([`DatagramTicket`]) holds the datagram itself.
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
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
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
    DatagramChoices, DatagramOverflow, DatagramQueues, DatagramQueuesFacts, DatagramQueuesFamily,
    DatagramQueuesFamilyOf, DatagramQueuesOf, DatagramQueuesRemainsOf, DatagramSide,
    application::{
        DatagramFrameLimits, DatagramSend, DatagramWriter, Datagrams, DetachedDatagrams,
        SendDatagramError,
    },
    frame_len_with_length, lock, payload_limit,
    send::{
        DatagramCell, DatagramIntent, DatagramProgress, DatagramSettlement, DatagramState,
        DatagramTicket, DatagramWithdrawCause, DriverPanicFlag, WithdrawReport, Withdrawal,
    },
};
use crate::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    send_strategy::{
        IntentTicketWithdraw, PublishOutcome, SendIntentHandle, SharedPublishTo, SharedSendStrategy,
    },
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::GetAt,
    v1::{
        Choices, CloseCauseOf, MakerChoices,
        application_handles::{
            connection::{
                ConnectionHandleRemainsOf, ConnectionHandleStateOf, LayerId, keep_waker, wake_all,
            },
            credential::{CredentialPointer, HandleCredential},
            established_layer::{EstablishedLayerHandle, LayerGone, LayerReach, lend_layer_or},
        },
        events::{DataLocation, DatagramDropped, NoEvents, SharedEvents},
        send::SendTypes,
        send_planning::{
            ComponentIntake, ComponentPublishing, HostSendStrategyTypes, IntakeOf, IntakeTicketOf,
            PlacedIntakeHandle, StrategyPublisherFor, StrategyPublisherOf,
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
/// strategy's intake gives back for a datagram's intent, `S` the side,
/// which gives what a datagram received is, `H` the handle of the intake
/// every intent of the queues is published through, on the driver's side
/// too, and `E` the handle the events of the
/// datagrams are given through, by default [`NoEvents`]: a datagram the
/// send queue takes and one a read gives the application move between the
/// application and the transport, and each one a queue drops for its bounds
/// is dropped ([`SharedEvents`]); each is given under the queues' lock.
/// Datagrams are sent with an [`Urgency`], to any active link path.
pub struct LockedDatagramQueues<Lc, K, S: DatagramSide, H, E = NoEvents> {
    shared: Arc<QueuesShare<Lc, K, S, H, E>>,
}

/// The default queues of the established layer.
pub type DefaultDatagramQueues<Lc, K, S, H, E = NoEvents> = LockedDatagramQueues<Lc, K, S, H, E>;

/// A datagram to send, as the send queue holds it.
type SendCell<K> = DatagramCell<K, AnyActiveLinkPath, Urgency>;

/// What the queues and their handles share.
struct QueuesShare<Lc, K, S: DatagramSide, H, E> {
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
    /// The handle of the send strategy's intake the datagrams' intents are
    /// published through.
    intake: H,
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
    /// The datagrams whose tickets are held through the shared connection,
    /// by their keys, until the tickets' credentials come back.
    tickets: BTreeMap<DatagramTicketKey, Arc<SendCell<K>>>,
    /// The key the next such ticket gets.
    next_ticket: u64,
}

/// Where the queues keep a datagram whose ticket is held through the
/// shared connection (`DatagramTicketKey`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DatagramTicketKey(u64);

/// What the queues of one layer leave once it ended
/// (`LockedDatagramQueuesRemains`): the datagrams received that the
/// application has not read, of the side's type `R`, how many were dropped
/// because the receive queue was full, and the progress of each datagram
/// whose ticket is held through the shared connection.
pub struct LockedDatagramQueuesRemains<R> {
    received: VecDeque<R>,
    dropped: u64,
    tickets: BTreeMap<DatagramTicketKey, Arc<DatagramProgress>>,
    panicked: Arc<DriverPanicFlag>,
}

impl<R> fmt::Debug for LockedDatagramQueuesRemains<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedDatagramQueuesRemains")
            .field("received", &self.received.len())
            .field("dropped", &self.dropped)
            .finish_non_exhaustive()
    }
}

impl<Lc, K, S: DatagramSide, H, E> fmt::Debug for LockedDatagramQueues<Lc, K, S, H, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedDatagramQueues")
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

impl<Lc, K, S, H, E> QueuesShare<Lc, K, S, H, E>
where
    K: IntentTicketWithdraw,
    S: DatagramSide,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    E: SharedEvents,
{
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
    /// the intake, with `parameters`, to `destination`; its ticket holds it
    /// apart from the connection.
    fn send(
        &self,
        payload: Bytes,
        parameters: Urgency,
        destination: AnyActiveLinkPath,
    ) -> Result<DatagramTicket<K, AnyActiveLinkPath, Urgency>, SendDatagramError<Lc>> {
        self.send_cell(payload, parameters, destination)
            .map(DatagramTicket::new)
    }

    /// Take `payload` into the send queue as [`send`](Self::send) does,
    /// and keep it in the table of the tickets held through the shared
    /// connection: its key.
    fn send_held(
        &self,
        payload: Bytes,
        parameters: Urgency,
        destination: AnyActiveLinkPath,
    ) -> Result<DatagramTicketKey, SendDatagramError<Lc>> {
        let cell = self.send_cell(payload, parameters, destination)?;
        let mut state = lock(&self.state);
        let key = DatagramTicketKey(state.next_ticket);
        state.next_ticket += 1;
        state.tickets.insert(key, cell);
        Ok(key)
    }

    /// The datagram of the held ticket `key`, taken out of the table when
    /// `take` says so.
    fn held_ticket(&self, key: DatagramTicketKey, take: bool) -> Option<Arc<SendCell<K>>> {
        let mut state = lock(&self.state);
        if take {
            state.tickets.remove(&key)
        } else {
            state.tickets.get(&key).cloned()
        }
    }

    /// What the queues leave once the layer ended: what was received and
    /// not read, the count of what was dropped, and the progress of the
    /// datagrams of the held tickets.
    fn remains(&self) -> LockedDatagramQueuesRemains<S::Received> {
        let mut state = lock(&self.state);
        state.received_bytes = 0;
        LockedDatagramQueuesRemains {
            received: core::mem::take(&mut state.received),
            dropped: state.dropped,
            tickets: core::mem::take(&mut state.tickets)
                .into_iter()
                .map(|(key, cell)| (key, Arc::clone(cell.progress().0)))
                .collect(),
            panicked: Arc::clone(&self.panicked),
        }
    }

    /// Take `payload` into the send queue, publishing its intent through
    /// the intake, with `parameters`, to `destination`: the datagram's cell.
    fn send_cell(
        &self,
        payload: Bytes,
        parameters: Urgency,
        destination: AnyActiveLinkPath,
    ) -> Result<Arc<SendCell<K>>, SendDatagramError<Lc>> {
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
        Self::resolve_waiting(&mut state, &self.intake);
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
        let ticket = self
            .intake
            .publish_to(intent.clone(), destination.current());
        let cell = DatagramCell::new(intent, ticket, destination, Arc::clone(&self.panicked));
        state.waiting_bytes += len;
        state.waiting.push_back(Arc::clone(&cell));
        if let Some(events) = self.events() {
            events.datagram_data_moved(len, DataLocation::Application, DataLocation::Transport);
        }
        Ok(cell)
    }

    /// What was written or withdrawn since leaves the send queue of
    /// `state`; what was not fulfilled goes on as its destination says,
    /// published again through `publish`, the intake, or withdrawn.
    fn resolve_waiting(state: &mut QueuesState<Lc, K, S::Received>, publish: &H) {
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
        let peer = self.peer_limit.unwrap_or(0);
        DatagramFrameLimits {
            guaranteed: peer.min(super::GUARANTEED_PAYLOAD),
            peer,
        }
    }
}

/// The kind of [`LockedDatagramQueues`].
#[derive(Debug)]
pub struct LockedDatagramQueuesFamily;

impl super::DatagramQueuesFamily for LockedDatagramQueuesFamily {
    type Config = LockedDatagramQueuesConfig;
    type Remains<S: DatagramSide> = LockedDatagramQueuesRemains<S::Received>;
    type Queues<
        Lc,
        I: ComponentPublishing<Self, DatagramIntent<Urgency>>,
        S: DatagramSide,
        E: SharedEvents + Clone + 'static,
    > = LockedDatagramQueues<
        Lc,
        <I as ComponentPublishing<Self, DatagramIntent<Urgency>>>::Ticket,
        S,
        <I as ComponentPublishing<Self, DatagramIntent<Urgency>>>::Intake,
        E,
    >;
}

/// The queues' capabilities can be held apart from the connection, on the
/// application's threads: they publish through an intake of their own, on
/// the driver's side too, and keep the intake's tickets either way. Their
/// kind gives the strategy types whose strategy gives intakes.
impl<I> ComponentPublishing<LockedDatagramQueuesFamily, DatagramIntent<Urgency>> for I
where
    I: HostSendStrategyTypes,
    I::Strategy: SharedSendStrategy<I>,
    IntakeOf<I>: PublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
{
    type Ticket = IntakeTicketOf<I, DatagramIntent<Urgency>>;
    type Intake =
        PlacedIntakeHandle<IntakeOf<I>, DatagramIntent<Urgency>, AnyActiveLinkPath, Self::Ticket>;
}

/// The intake is the core's, with the place of the datagram intents fixed.
impl<I, Idx> ComponentIntake<LockedDatagramQueuesFamily, DatagramIntent<Urgency>, Idx> for I
where
    I: HostSendStrategyTypes,
    I::Strategy: SharedSendStrategy<I>,
    IntakeOf<I>: SharedPublishTo<DatagramIntent<Urgency>, AnyActiveLinkPath, Idx>,
{
    fn intake(strategy: &mut I::Strategy) -> Self::Intake {
        PlacedIntakeHandle::new::<Idx>(strategy.intake())
    }
}

/// The queues ignore the publisher they are lent: they publish through the
/// intake they keep.
impl<Lc, I, K, S, H, E> DatagramQueues<Lc, I> for LockedDatagramQueues<Lc, K, S, H, E>
where
    I: HostSendStrategyTypes,
    K: IntentTicketWithdraw,
    S: DatagramSide,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    E: SharedEvents,
{
    type Config = LockedDatagramQueuesConfig;
    type Handle = LockedDatagramQueuesHandle<Lc, K, S, H, E>;
    type Events = E;
    type Intake = H;
    type Remains = LockedDatagramQueuesRemains<S::Received>;

    fn new(
        facts: DatagramQueuesFacts,
        config: LockedDatagramQueuesConfig,
        events: E,
        intake: H,
    ) -> Self {
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
                    tickets: BTreeMap::new(),
                    next_ticket: 0,
                }),
                events,
                intake,
            }),
        }
    }

    fn handle(&self) -> LockedDatagramQueuesHandle<Lc, K, S, H, E> {
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

    fn remains(&mut self) -> LockedDatagramQueuesRemains<S::Received> {
        self.shared.remains()
    }

    fn resolve_unfulfilled<Ij>(&mut self, _: &mut StrategyPublisherOf<I>)
    where
        StrategyPublisherOf<I>: StrategyPublisherFor<DatagramIntent<Urgency>, Ij>,
    {
        let shared = &*self.shared;
        QueuesShare::<Lc, K, S, H, E>::resolve_waiting(&mut lock(&shared.state), &shared.intake);
    }
}

/// The handle of a [`LockedDatagramQueues`] (`LockedDatagramQueuesHandle`):
/// it shares the queues' state. The capability of the established layer's
/// handle takes it from the queues it is lent. A clone is the same handle.
pub struct LockedDatagramQueuesHandle<Lc, K, S: DatagramSide, H, E = NoEvents> {
    shared: Arc<QueuesShare<Lc, K, S, H, E>>,
}

impl<Lc, K, S: DatagramSide, H, E> Clone for LockedDatagramQueuesHandle<Lc, K, S, H, E> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<Lc, K, S: DatagramSide, H, E> QueuesShare<Lc, K, S, H, E> {
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

impl<Lc, K, S: DatagramSide, H, E> fmt::Debug for LockedDatagramQueuesHandle<Lc, K, S, H, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedDatagramQueuesHandle")
            .finish_non_exhaustive()
    }
}

impl<Lc, K, S: DatagramSide, H, E> LockedDatagramQueuesHandle<Lc, K, S, H, E> {
    /// How many datagrams received were dropped because the receive queue
    /// was full; it only grows.
    pub fn dropped_datagrams(&self) -> u64 {
        lock(&self.shared.state).dropped
    }
}

/// What an operation through the shared connection reaches of the queues
/// of a layer: the queues' shared state, where the handle the datagram
/// intents are published through is, while the layer is there; otherwise
/// how it ended and what its queues left, which is there unless the layer
/// had no queues.
enum QueuesReach<'a, Lc, K, S: DatagramSide, H, E> {
    Queues(&'a QueuesShare<Lc, K, S, H, E>),
    Gone(
        Option<&'a mut LockedDatagramQueuesRemains<S::Received>>,
        LayerEnd<Lc>,
    ),
}

/// Lend what `op` reaches of the queues of the layer `layer` of
/// `connection` once: see [`QueuesReach`]. `K`, `D`, `H` and `E` are the
/// queues' parameters, as their handle names them. `Ie`, `Ic` and `Ir` are
/// where the connection handle's state is in the layer's lineage and in the
/// connection node's, and where version 1's part is in what the parts keep
/// after the end; `Iq` where the queues are in the layer's lineage; `Ik`
/// and `Irq` where what the queues of the layers that ended left is in the
/// connection node and in what the parts keep after the end.
#[allow(clippy::type_complexity)] // the reach of six type parameters
fn reach_queues<T, L, S, R, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq>(
    connection: &S,
    layer: LayerId,
    op: impl FnOnce(QueuesReach<'_, CloseCauseOf<T, L>, K, D, H, E>) -> R,
) -> R
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    K: IntentTicketWithdraw,
    D: DatagramSide,
    E: SharedEvents,
    DatagramQueuesOf<T, L>: DatagramQueues<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, H, E>,
        >,
    DatagramQueuesFamilyOf<T>: DatagramQueuesFamily<
        Remains<<T as MakerChoices>::Side> = LockedDatagramQueuesRemains<D::Received>,
    >,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    let mut op = Some(op);
    let reached = lend_layer_or::<T, L, S, _, Ie, Ic, Ir>(connection, layer, |reach| {
        let op = op.take().expect("called once");
        match reach {
            LayerReach::Layer(lineage, _) => {
                let shared = lineage.get::<DatagramQueuesOf<T, L>, Iq>().handle().shared;
                op(QueuesReach::Queues(&shared))
            }
            LayerReach::Gone(LayerGone::Connection(mut lineage), end) => {
                let mut kept = lineage.get_mut::<DatagramQueuesRemainsOf<T>, Ik>();
                op(QueuesReach::Gone(kept.layer_mut(layer), end))
            }
            LayerReach::Gone(LayerGone::Ended(remains), end) => {
                let kept = Selector::<DatagramQueuesRemainsOf<T>, Irq>::get_mut(remains);
                op(QueuesReach::Gone(kept.layer_mut(layer), end))
            }
        }
    });
    match reached {
        Ok(done) => done,
        Err(end) => {
            let op = op.take().expect("not called");
            op(QueuesReach::Gone(None, end))
        }
    }
}

/// The handle of the established layer `T`, `L`, `S`, `A` whose queues are
/// the default ones.
impl<T, L, S, A> EstablishedLayerHandle<T, L, S, A>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
{
    /// How many datagrams the layer received were dropped because the
    /// receive queue was full; it only grows, and is still read once the
    /// layer ended.
    ///
    /// `K`, `D`, `H` and `E` are the queues' parameters, as their handle
    /// names them. `Ie`, `Ic` and `Ir` are where the connection handle's
    /// state is in the layer's lineage and in the connection node's, and
    /// where version 1's part is in what the parts keep after the end; `Iq`
    /// where the queues are in the layer's lineage; `Ik` and `Irq` where
    /// what the queues of the layers that ended left is in the connection
    /// node and in what the parts keep after the end. The compiler infers
    /// them.
    pub fn dropped_datagrams<K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq>(&self) -> u64
    where
        T: Choices<Side: DatagramSide, Host: DatagramChoices>,
        L: LineagePartList<T> + ConnectionErrorsOf,
        S: SharedConnection<Driver: LendNode<T, L>>,
        SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
        K: IntentTicketWithdraw,
        D: DatagramSide,
        E: SharedEvents,
        DatagramQueuesOf<T, L>: DatagramQueues<
                CloseCauseOf<T, L>,
                SendTypes<T, L>,
                Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, H, E>,
            >,
        DatagramQueuesFamilyOf<T>: DatagramQueuesFamily<
            Remains<<T as MakerChoices>::Side> = LockedDatagramQueuesRemains<D::Received>,
        >,
        H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>
            + Selector<DatagramQueuesRemainsOf<T>, Irq>,
        for<'v> <L as LineageLists<'v, T>>::Established:
            GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
        for<'v> <L as LineageLists<'v, T>>::Connection:
            GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
    {
        let (connection, layer) = self.reach();
        reach_queues::<T, L, S, _, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq>(
            connection,
            layer,
            |reach| match reach {
                QueuesReach::Queues(shared) => lock(&shared.state).dropped,
                QueuesReach::Gone(kept, _) => kept.map_or(0, |kept| kept.dropped),
            },
        )
    }
}

/// The capability of the default queues through the shared connection, on
/// the handle of an established layer: each call, and each poll of a
/// receive, lends the layer once. The writer holds the connection and the
/// layer's identity; a ticket also holds its datagram's key in the queues
/// and its credential. Once the layer ended, a receive reads what the
/// queues left until nothing is left, then reports the end. The places
/// are as for [`dropped_datagrams`](EstablishedLayerHandle::dropped_datagrams).
impl<T, L, S, A, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq> Datagrams<(Ie, Ic, Ir, Iq, Ik, Irq)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    K: IntentTicketWithdraw,
    D: DatagramSide,
    E: SharedEvents,
    DatagramQueuesOf<T, L>: DatagramQueues<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, H, E>,
        >,
    DatagramQueuesFamilyOf<T>: DatagramQueuesFamily<
        Remains<<T as MakerChoices>::Side> = LockedDatagramQueuesRemains<D::Received>,
    >,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    type Received = D::Received;
    type SendCapability = SharedDatagramSend<T, L, S, (Ie, Ic, Ir, Iq, Ik, Irq)>;
    type CloseCause = CloseCauseOf<T, L>;

    fn datagram_writer(&self) -> DatagramWriter<Self::SendCapability, NoSendOptions> {
        let (connection, layer) = self.reach();
        DatagramWriter::new(SharedDatagramSend {
            connection: connection.clone(),
            layer,
            places: PhantomData,
        })
    }

    fn recv_datagram(
        &self,
    ) -> impl Future<Output = Result<D::Received, LayerEndedError<CloseCauseOf<T, L>>>> {
        poll_fn(move |cx| {
            let (connection, layer) = self.reach();
            reach_queues::<T, L, S, _, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq>(
                connection,
                layer,
                |reach| match reach {
                    QueuesReach::Queues(shared) => shared.poll_receive(cx),
                    QueuesReach::Gone(kept, end) => Poll::Ready(
                        kept.and_then(|kept| kept.received.pop_front())
                            .ok_or_else(|| LayerEndedError::new(end)),
                    ),
                },
            )
        })
    }
}

/// The capability of the default queues with an independent share of the
/// send queue: the writer lends the layer once, when it is taken, and holds
/// the queues' shared state, where the handle of the intake they publish
/// through is, from then on, apart from the connection; one taken once the
/// layer ended reports the end. `Ie`, `Ic`, `Ir` and `Iq` are as for
/// [`dropped_datagrams`](EstablishedLayerHandle::dropped_datagrams).
impl<T, L, S, A, K, D, H, E, Ie, Ic, Ir, Iq> DetachedDatagrams<(Ie, Ic, Ir, Iq)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    K: IntentTicketWithdraw,
    D: DatagramSide,
    E: SharedEvents,
    DatagramQueuesOf<T, L>: DatagramQueues<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, H, E>,
        >,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
{
    type SendShare = LockedDatagramSendShare<CloseCauseOf<T, L>, K, D, H, E>;

    fn datagram_writer_detached(&self) -> DatagramWriter<Self::SendShare, NoSendOptions> {
        let queue = self
            .lend_layer::<_, Ie, Ic, Ir>(|lineage, _| {
                SendQueueReach::Queues(lineage.get::<DatagramQueuesOf<T, L>, Iq>().handle().shared)
            })
            .unwrap_or_else(SendQueueReach::Ended);
        DatagramWriter::new(LockedDatagramSendShare { queue })
    }
}

// ---- through the shared connection ----

/// The capability of the send queue of the default queues through the
/// shared connection (`SharedDatagramSend`), which a [`DatagramWriter`]
/// holds: the connection in its wrapper and the layer's identity. `I` is
/// where the components it is lent are and the place of the datagram
/// intents, as [`Datagrams`] names them. It holds no credential: dropping
/// it means nothing to the protocol. A clone sends to the same queue.
pub struct SharedDatagramSend<T, L, S, I> {
    connection: S,
    layer: LayerId,
    #[allow(clippy::type_complexity)] // a marker of three type parameters
    places: PhantomData<fn() -> (T, L, I)>,
}

impl<T, L, S: Clone, I> Clone for SharedDatagramSend<T, L, S, I> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            layer: self.layer,
            places: PhantomData,
        }
    }
}

impl<T, L, S, I> fmt::Debug for SharedDatagramSend<T, L, S, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedDatagramSend").finish_non_exhaustive()
    }
}

/// Datagrams are sent with an urgency, to any active link path; each send
/// lends the layer once.
impl<T, L, S, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq> DatagramSend
    for SharedDatagramSend<T, L, S, (Ie, Ic, Ir, Iq, Ik, Irq)>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    K: IntentTicketWithdraw,
    D: DatagramSide,
    E: SharedEvents,
    DatagramQueuesOf<T, L>: DatagramQueues<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, H, E>,
        >,
    DatagramQueuesFamilyOf<T>: DatagramQueuesFamily<
        Remains<<T as MakerChoices>::Side> = LockedDatagramQueuesRemains<D::Received>,
    >,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    type Parameters = Urgency;
    type Destination = AnyActiveLinkPath;
    type CloseCause = CloseCauseOf<T, L>;
    type Ticket = SharedDatagramTicket<T, L, S, (Ie, Ic, Ir, Iq, Ik, Irq), HandleCredential>;

    fn send_with(
        &self,
        payload: Bytes,
        parameters: &Urgency,
        destination: &AnyActiveLinkPath,
    ) -> Result<Self::Ticket, SendDatagramError<CloseCauseOf<T, L>>> {
        let key = reach_queues::<T, L, S, _, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq>(
            &self.connection,
            self.layer,
            |reach| match reach {
                QueuesReach::Queues(shared) => shared.send_held(payload, *parameters, *destination),
                QueuesReach::Gone(_, end) => Err(LayerEndedError::new(end).into()),
            },
        )?;
        Ok(
            SharedDatagramTicket {
                connection: self.connection.clone(),
                layer: self.layer,
                key,
                credential: Some(HandleCredential::new()),
                give_back: SharedDatagramTicket::<
                    T,
                    L,
                    S,
                    (Ie, Ic, Ir, Iq, Ik, Irq),
                    HandleCredential,
                >::give_back,
                places: PhantomData,
            },
        )
    }

    /// Nothing fits once the layer ended.
    fn datagram_limits(&self) -> DatagramFrameLimits {
        reach_queues::<T, L, S, _, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq>(
            &self.connection,
            self.layer,
            |reach| match reach {
                QueuesReach::Queues(shared) => shared.limits(),
                QueuesReach::Gone(..) => DatagramFrameLimits {
                    guaranteed: 0,
                    peer: 0,
                },
            },
        )
    }
}

/// What hands a ticket's credential back to the queues: the connection,
/// the layer and the datagram's key; the datagram is withdrawn.
type GiveBack<S> = fn(&S, LayerId, DatagramTicketKey);

/// The ticket of one datagram sent through the shared connection
/// (`SharedDatagramTicket`): the connection in its wrapper, the layer's
/// identity, the datagram's key in the queues and the pointer `C` to the
/// ticket's credential. It tells where the datagram stands and waits for
/// it to be settled, as a [`DatagramTicket`] does; each call, and each poll
/// of a wait, lends the layer once, and once the layer ended reads what
/// the queues left.
///
/// It can be cloned where `C` can: sent with the credential itself, it is
/// turned into one with a shared credential by
/// [`into_shared`](Self::into_shared). Once the last holder of the
/// credential drops its ticket, the datagram is withdrawn, if it was not
/// written into a packet yet; [`release`](Self::release) lets it go
/// without withdrawing it.
#[must_use = "dropping the ticket withdraws the datagram; `release` lets it go without that"]
pub struct SharedDatagramTicket<T, L, S, I, C: CredentialPointer> {
    connection: S,
    layer: LayerId,
    key: DatagramTicketKey,
    /// `None` once it was handed back, by a release, a withdrawal or a
    /// move to a shared pointer.
    credential: Option<C>,
    give_back: GiveBack<S>,
    #[allow(clippy::type_complexity)] // a marker of three type parameters
    places: PhantomData<fn() -> (T, L, I)>,
}

impl<T, L, S: Clone, I, C: CredentialPointer + Clone> Clone
    for SharedDatagramTicket<T, L, S, I, C>
{
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            layer: self.layer,
            key: self.key,
            credential: self.credential.clone(),
            give_back: self.give_back,
            places: PhantomData,
        }
    }
}

impl<T, L, S, I, C: CredentialPointer> fmt::Debug for SharedDatagramTicket<T, L, S, I, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedDatagramTicket")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// The last holder of the credential withdraws the datagram when it drops
/// its ticket.
impl<T, L, S, I, C: CredentialPointer> Drop for SharedDatagramTicket<T, L, S, I, C> {
    fn drop(&mut self) {
        if self
            .credential
            .take()
            .and_then(C::into_credential)
            .is_some()
        {
            (self.give_back)(&self.connection, self.layer, self.key);
        }
    }
}

impl<T, L, S: Clone, I> SharedDatagramTicket<T, L, S, I, HandleCredential> {
    /// The same ticket with the credential behind the shared pointer `Q`
    /// ([`Arc`] or [`Rc`](alloc::rc::Rc)), so that it can be cloned.
    pub fn into_shared<Q>(mut self) -> SharedDatagramTicket<T, L, S, I, Q>
    where
        Q: CredentialPointer + From<HandleCredential>,
    {
        SharedDatagramTicket {
            connection: self.connection.clone(),
            layer: self.layer,
            key: self.key,
            credential: self.credential.take().map(Q::from),
            give_back: self.give_back,
            places: PhantomData,
        }
    }
}

/// Where a ticket through the shared connection finds its datagram.
enum TicketAt<K> {
    /// In the queues of its layer.
    Queued(Arc<SendCell<K>>),
    /// In what the queues left once the layer ended.
    Kept(Arc<DatagramProgress>, Arc<DriverPanicFlag>),
    /// Nowhere: the layer ended without leaving it.
    Gone,
}

/// The ticket's operations on the default queues; the places are as for
/// [`dropped_datagrams`](EstablishedLayerHandle::dropped_datagrams).
impl<T, L, S, C, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq>
    SharedDatagramTicket<T, L, S, (Ie, Ic, Ir, Iq, Ik, Irq), C>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    K: IntentTicketWithdraw,
    D: DatagramSide,
    E: SharedEvents,
    DatagramQueuesOf<T, L>: DatagramQueues<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, H, E>,
        >,
    DatagramQueuesFamilyOf<T>: DatagramQueuesFamily<
        Remains<<T as MakerChoices>::Side> = LockedDatagramQueuesRemains<D::Received>,
    >,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
    C: CredentialPointer,
{
    /// Where the datagram of `key` is, taken out of the queues' table, or
    /// out of what they left, when `take` says so.
    fn find(connection: &S, layer: LayerId, key: DatagramTicketKey, take: bool) -> TicketAt<K> {
        reach_queues::<T, L, S, _, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq>(
            connection,
            layer,
            |reach| match reach {
                QueuesReach::Queues(shared) => shared
                    .held_ticket(key, take)
                    .map_or(TicketAt::Gone, TicketAt::Queued),
                QueuesReach::Gone(Some(kept), _) => {
                    let progress = if take {
                        kept.tickets.remove(&key)
                    } else {
                        kept.tickets.get(&key).cloned()
                    };
                    progress.map_or(TicketAt::Gone, |progress| {
                        TicketAt::Kept(progress, Arc::clone(&kept.panicked))
                    })
                }
                QueuesReach::Gone(None, _) => TicketAt::Gone,
            },
        )
    }

    /// Hand the credential of `key` back: the datagram leaves the table
    /// and is withdrawn, if it was not written into a packet yet.
    fn give_back(connection: &S, layer: LayerId, key: DatagramTicketKey) {
        if let TicketAt::Queued(cell) = Self::find(connection, layer, key, true) {
            cell.withdraw_for_holder();
        }
    }

    /// Where the datagram stands now; once the layer ended, as its queues
    /// left it, or withdrawn as the layer ended if they left nothing of it.
    pub fn state(&self) -> DatagramState {
        let gone = DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded);
        match Self::find(&self.connection, self.layer, self.key, false) {
            TicketAt::Queued(cell) => {
                let (progress, panicked) = cell.progress();
                progress.state(panicked).unwrap_or(gone)
            }
            TicketAt::Kept(progress, panicked) => progress.state(&panicked).unwrap_or(gone),
            TicketAt::Gone => gone,
        }
    }

    /// Done once the datagram was acknowledged, declared lost, or withdrawn
    /// without its holder asking, as [`DatagramTicket::settled`] is.
    pub fn settled(&mut self) -> impl Future<Output = DatagramSettlement> + '_ {
        poll_fn(
            move |cx| match Self::find(&self.connection, self.layer, self.key, false) {
                TicketAt::Queued(cell) => {
                    let (progress, panicked) = cell.progress();
                    progress.poll_settled(cx, panicked)
                }
                TicketAt::Kept(progress, panicked) => progress.poll_settled(cx, &panicked),
                TicketAt::Gone => Poll::Ready(DatagramSettlement::Withdrawn(
                    DatagramWithdrawCause::LayerEnded,
                )),
            },
        )
    }

    /// Let the datagram go without withdrawing it, if this holder is the
    /// last of its credential: it is still sent, and nothing hears whether
    /// it is acknowledged or lost. Otherwise only this holder lets go.
    pub fn release(mut self) {
        if self
            .credential
            .take()
            .and_then(C::into_credential)
            .is_some()
        {
            let _ = Self::find(&self.connection, self.layer, self.key, true);
        }
    }
}

impl<T, L, S, K, D, H, E, Ie, Ic, Ir, Iq, Ik, Irq>
    SharedDatagramTicket<T, L, S, (Ie, Ic, Ir, Iq, Ik, Irq), HandleCredential>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    K: IntentTicketWithdraw,
    D: DatagramSide,
    E: SharedEvents,
    DatagramQueuesOf<T, L>: DatagramQueues<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            Handle = LockedDatagramQueuesHandle<CloseCauseOf<T, L>, K, D, H, E>,
        >,
    DatagramQueuesFamilyOf<T>: DatagramQueuesFamily<
        Remains<<T as MakerChoices>::Side> = LockedDatagramQueuesRemains<D::Received>,
    >,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    /// Withdraw the datagram, as [`DatagramTicket::withdraw`] does; once
    /// the layer ended, what withdrawing would have reported then. Only the
    /// one holder of the credential itself withdraws.
    pub fn withdraw(mut self) -> WithdrawReport {
        self.credential = None;
        match Self::find(&self.connection, self.layer, self.key, true) {
            TicketAt::Queued(cell) => cell.withdraw_for_holder(),
            TicketAt::Kept(progress, _) => progress.withdraw_report(),
            TicketAt::Gone => WithdrawReport::Withdrawn,
        }
    }
}

/// This side's share of the send queue of a [`LockedDatagramQueues`]
/// (`LockedDatagramSendShare`), whose intents are published through the
/// handle `H` the queues keep; one taken once its layer ended reports the
/// end.
pub struct LockedDatagramSendShare<Lc, K, S: DatagramSide, H, E = NoEvents> {
    queue: SendQueueReach<Lc, K, S, H, E>,
}

/// What a share of the send queue reaches.
enum SendQueueReach<Lc, K, S: DatagramSide, H, E> {
    /// The queues' shared state.
    Queues(Arc<QueuesShare<Lc, K, S, H, E>>),
    /// Nothing: the layer had ended when the share was taken.
    Ended(LayerEnd<Lc>),
}

impl<Lc, K, S: DatagramSide, H, E> Clone for LockedDatagramSendShare<Lc, K, S, H, E> {
    fn clone(&self) -> Self {
        let queue = match &self.queue {
            SendQueueReach::Queues(shared) => SendQueueReach::Queues(Arc::clone(shared)),
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
            SendQueueReach::Queues(shared) => shared.send(payload, *parameters, *destination),
            SendQueueReach::Ended(end) => Err(LayerEndedError::new(end.clone()).into()),
        }
    }

    /// Nothing fits once the layer ended.
    fn datagram_limits(&self) -> DatagramFrameLimits {
        match &self.queue {
            SendQueueReach::Queues(shared) => shared.limits(),
            SendQueueReach::Ended(_) => DatagramFrameLimits {
                guaranteed: 0,
                peer: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests;
