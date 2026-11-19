//! Queues of the established layer that also give a share of their send
//! queue held apart from the connection: one lock over both bounded queues,
//! which the connection and the application's handles share
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
//! - **Sending.** A datagram waits in the send queue, by its key
//!   ([`DatagramKey`]), from when it is sent until it is written into a
//!   packet or withdrawn; the queue's bounds are counted over those
//!   waiting. When one more is sent, the queue refuses it or withdraws the
//!   oldest ones to make room, as it is configured. A datagram whose ticket
//!   was released stays in the queue until it is written, so the
//!   strategy's ticket stays with it. Every intent is published through the
//!   intake the queues keep, on the driver's side too; the publisher they
//!   are lent is left as it is.
//! - **The end of the layer.** What was received is still read; then
//!   every read reports the end, and so does every send. The datagrams
//!   still waiting are withdrawn, and those in flight are lost. What was
//!   received and not read, the count of what was dropped, and the
//!   progress of the datagrams whose tickets are held through the shared
//!   connection go into the connection node
//!   ([`LockedDatagramQueuesRemains`]), where the layer's handle and those
//!   tickets read them after the layer is gone.
//! - **Tickets.** A ticket held through the shared connection
//!   ([`SharedDatagramTicket`](super::shared::SharedDatagramTicket)) finds
//!   its datagram by its key, in a table the queues keep until the ticket's
//!   credential comes back; one held apart from the connection
//!   ([`DatagramTicket`]) holds the datagram itself. Both read the
//!   strategy's ticket of the intake, which tells when a datagram waits as
//!   too large for now.
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
//! source writes under the queues' lock: it finds the payload by the key,
//! moves the progress to sent under it, and the datagram leaves the send
//! queue at once; an acknowledgment or a loss finds the progress by the key
//! under it too. A ticket apart from the connection withdraws through the
//! progress and the route alone, and the queue counts the datagram as gone
//! the next time it looks. The events of the datagrams are given under the
//! queues' lock.

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    fmt,
    task::{Context, Poll, Waker},
};
use std::sync::{Mutex, OnceLock};

use bytes::{Buf, Bytes};
use sakuya_stream::{
    connection::{LayerEnd, LayerEndedError},
    send_options::{
        NoSendOptions,
        destination::{AnyActiveLinkPath, SendDestination, Unfulfilled},
        urgency::Urgency,
    },
};
use sakuya_wire::{
    datagram::DatagramFrame, parts::Selector, v1::encryption_level::EncryptionLevel,
};

use super::{
    DatagramChoices, DatagramLayerRemains, DatagramOverflow, DatagramQueueBounds, DatagramQueues,
    DatagramQueuesFacts, DatagramQueuesFamilyOf, DatagramQueuesOf, DatagramSide,
    application::{
        DatagramFrameLimits, DatagramSend, DatagramWriter, DetachedDatagrams, SendDatagramError,
    },
    frame_len_with_length, lock, payload_limit,
    send::{
        DatagramCell, DatagramIntent, DatagramKey, DatagramProgress, DatagramSettlement,
        DatagramState, DatagramSummary, DatagramTicket, DatagramWithdrawCause, DriverPanicFlag,
        HeldDatagram, WithdrawReport, Withdrawal, held_datagram_gone, write_datagram,
    },
};
use crate::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    feedback::InjectSummary,
    send_strategy::{
        IntentTicketChanges, IntentTicketState, IntentTicketWithdraw, PublishOutcome,
        SendIntentHandle, SharedPublishTo, SharedSendStrategy,
    },
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::GetAt,
    v1::{
        Choices,
        application_handles::{
            connection::{
                ConnectionHandleRemainsOf, ConnectionHandleStateOf, keep_waker, wake_all,
            },
            established_layer::EstablishedLayerHandle,
        },
        events::{DataLocation, DatagramDropped, NoEvents, SharedEvents},
        send::SendTypes,
        send_planning::{
            ComponentIntake, ComponentPublishing, HostSendStrategyTypes, IntakeOf, IntakeTicketOf,
            PlacedIntakeHandle, StrategyPublisherForTicket, StrategyPublisherOf,
        },
    },
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

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
    /// The datagrams waiting to be sent, by their keys: the first is the
    /// oldest. Those withdrawn apart from the queues leave it the next
    /// time the queue looks.
    waiting: BTreeMap<DatagramKey, Arc<SendCell<K>>>,
    waiting_bytes: usize,
    /// The datagrams written into a packet whose fate is not known yet, or
    /// declared lost, so that a late acknowledgment may come, while their
    /// tickets are held: what an acknowledgment or a loss finds, and what a
    /// panic of the driver wakes the tickets of. Those settled or let go
    /// leave it each time the send queue is resolved.
    in_flight: BTreeMap<DatagramKey, Weak<SendCell<K>>>,
    /// The key the next datagram gets.
    next_key: DatagramKey,
    /// How the layer ended, once it did.
    end: Option<LayerEnd<Lc>>,
    /// The datagrams whose tickets are held through the shared connection,
    /// by their keys, until the tickets' credentials come back.
    tickets: BTreeMap<DatagramKey, Arc<SendCell<K>>>,
}

/// What the queues of one layer leave once it ended
/// (`LockedDatagramQueuesRemains`): the datagrams received that the
/// application has not read, of the side's type `R`, how many were dropped
/// because the receive queue was full, and the progress of each datagram
/// whose ticket is held through the shared connection.
pub struct LockedDatagramQueuesRemains<R> {
    received: VecDeque<R>,
    dropped: u64,
    tickets: BTreeMap<DatagramKey, Arc<DatagramProgress>>,
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

/// The progress of each held datagram is as the layer's end left it, and
/// read as its ticket would read it.
impl<R> DatagramLayerRemains for LockedDatagramQueuesRemains<R> {
    type Received = R;

    fn pop_received(&mut self) -> Option<R> {
        self.received.pop_front()
    }

    fn dropped(&self) -> u64 {
        self.dropped
    }

    fn ticket_state(&self, key: DatagramKey) -> Option<DatagramState> {
        let progress = self.tickets.get(&key)?;
        Some(
            progress
                .state(&self.panicked)
                .unwrap_or(DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded)),
        )
    }

    fn ticket_settlement(&self, key: DatagramKey) -> Option<DatagramSettlement> {
        self.ticket_state(key)
            .map(super::send::settlement_after_end)
    }

    fn take_ticket(&mut self, key: DatagramKey) -> Option<WithdrawReport> {
        self.tickets
            .remove(&key)
            .map(|progress| progress.withdraw_report())
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

    /// The layer ended as `end`: the waiting datagrams are withdrawn, those
    /// in flight are lost, as nothing settles them after, and who waits for
    /// one received hears of it.
    fn end(&self, end: LayerEnd<Lc>) {
        let mut state = lock(&self.state);
        if state.end.is_some() {
            return;
        }
        state.end = Some(end);
        wake_all(&mut state.receivers);
        state.waiting_bytes = 0;
        for cell in core::mem::take(&mut state.waiting).into_values() {
            cell.withdraw(Withdrawal::Cause(DatagramWithdrawCause::LayerEnded));
        }
        for cell in core::mem::take(&mut state.in_flight).into_values() {
            if let Some(cell) = cell.upgrade() {
                cell.settle(false);
            }
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
        let mut state = lock(&self.state);
        self.send_cell(&mut state, payload, parameters, destination)
            .map(|(_, cell)| DatagramTicket::new(cell))
    }

    /// Take `payload` into the send queue as [`send`](Self::send) does,
    /// and keep it in the table of the tickets held through the shared
    /// connection: its key.
    fn send_held(
        &self,
        payload: Bytes,
        parameters: Urgency,
        destination: AnyActiveLinkPath,
    ) -> Result<DatagramKey, SendDatagramError<Lc>> {
        let mut state = lock(&self.state);
        let (key, cell) = self.send_cell(&mut state, payload, parameters, destination)?;
        state.tickets.insert(key, cell);
        Ok(key)
    }

    /// Take `payload` into the send queue of `state`, publishing its intent
    /// through the intake, with `parameters`, to `destination`: the
    /// datagram's key, the next of `state`, and its cell.
    fn send_cell(
        &self,
        state: &mut QueuesState<Lc, K, S::Received>,
        payload: Bytes,
        parameters: Urgency,
        destination: AnyActiveLinkPath,
    ) -> Result<(DatagramKey, Arc<SendCell<K>>), SendDatagramError<Lc>> {
        let Some(limit) = self.peer_limit else {
            return Err(SendDatagramError::NotSupportedByPeer);
        };
        let len = payload.len();
        if frame_len_with_length(len) > self.peer_frame_limit {
            return Err(SendDatagramError::TooLarge { limit });
        }
        let bounds = self.config.send;
        if let Some(end) = self.panic_end.get().or(state.end.as_ref()) {
            return Err(LayerEndedError::new(end.clone()).into());
        }
        if len > bounds.bytes {
            // larger than the whole queue: no room can be made for it
            return Err(SendDatagramError::QueueFull);
        }
        Self::resolve_waiting(state);
        let fits = |state: &QueuesState<Lc, K, S::Received>| {
            state.waiting.len() < bounds.datagrams.get()
                && state.waiting_bytes.saturating_add(len) <= bounds.bytes
        };
        while !fits(state) {
            let oldest = match bounds.overflow {
                DatagramOverflow::DropOldest => state.waiting.pop_first(),
                DatagramOverflow::RejectNew => None,
            };
            let Some((_, oldest)) = oldest else {
                return Err(SendDatagramError::QueueFull);
            };
            state.waiting_bytes -= oldest.len();
            self.dropped(oldest.len(), DatagramDropped::SendQueueFull);
            // withdrawn by its holder meanwhile, it leaves the queue all
            // the same
            oldest.withdraw(Withdrawal::Cause(DatagramWithdrawCause::DroppedOldest));
        }
        let key = state.next_key;
        state.next_key = key.next();
        let ticket = self.intake.publish_to(
            DatagramIntent::new(key, len, parameters),
            destination.current(),
        );
        let cell = DatagramCell::new(
            key,
            payload,
            parameters,
            ticket,
            destination,
            Arc::clone(&self.panicked),
        );
        state.waiting_bytes += len;
        state.waiting.insert(key, Arc::clone(&cell));
        if let Some(events) = self.events() {
            events.datagram_data_moved(len, DataLocation::Application, DataLocation::Transport);
        }
        Ok((key, cell))
    }

    /// What was withdrawn apart from the queues leaves the send queue of
    /// `state`, and what was settled or let go leaves the datagrams in
    /// flight.
    fn resolve_waiting(state: &mut QueuesState<Lc, K, S::Received>) {
        state.in_flight.retain(|_, cell| {
            cell.upgrade()
                .is_some_and(|cell| cell.awaits_acknowledgment())
        });
        let mut gone = 0;
        state.waiting.retain(|_, cell| {
            let waiting = cell.is_waiting();
            if !waiting {
                gone += cell.len();
            }
            waiting
        });
        state.waiting_bytes -= gone;
    }

    /// Write the datagram of `key`, if it waits and its frame fits: it
    /// leaves the send queue for the datagrams in flight.
    fn supply<W, Q, Idx>(
        &self,
        key: DatagramKey,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DatagramSummary, Idx>,
        Q: PacketPosition,
    {
        let mut state = lock(&self.state);
        let Some(cell) = state.waiting.get(&key).cloned() else {
            return Supplied::Open(packet);
        };
        let (supplied, written) = write_datagram(
            cell.payload().clone(),
            packet,
            DatagramSummary { key },
            || cell.start_writing(),
        );
        if written || !cell.is_waiting() {
            state.waiting.remove(&key);
            state.waiting_bytes -= cell.len();
        }
        if written {
            state.in_flight.insert(key, Arc::downgrade(&cell));
        }
        supplied
    }

    /// The packet the datagram of `key` was written into was acknowledged,
    /// or, if `delivered` is false, declared lost.
    fn settle(&self, key: DatagramKey, delivered: bool) {
        let mut state = lock(&self.state);
        let Some(cell) = state.in_flight.get(&key).and_then(Weak::upgrade) else {
            state.in_flight.remove(&key);
            return;
        };
        cell.settle(delivered);
        if !cell.awaits_acknowledgment() {
            state.in_flight.remove(&key);
        }
    }

    /// The intent of the datagram of `key` was not fulfilled for `cause`:
    /// its destination falls back at once, through the intake.
    fn unfulfilled(&self, key: DatagramKey, cause: Unfulfilled) {
        let mut state = lock(&self.state);
        let Some(cell) = state.waiting.get(&key).cloned() else {
            return;
        };
        cell.resolve_unfulfilled(cause, &self.intake);
        if !cell.is_waiting() {
            state.waiting.remove(&key);
            state.waiting_bytes -= cell.len();
        }
    }

    /// The datagram of the held ticket `key`, taken out of the table when
    /// `take` says so.
    fn held_ticket(&self, key: DatagramKey, take: bool) -> Option<Arc<SendCell<K>>> {
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
/// intake they keep, and their tickets, the intake's, tell by themselves
/// whether a datagram waits as too large for now.
impl<Lc, I, K, S, H, E> DatagramQueues<Lc, I> for LockedDatagramQueues<Lc, K, S, H, E>
where
    I: HostSendStrategyTypes,
    K: IntentTicketWithdraw + IntentTicketState,
    S: DatagramSide,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    E: SharedEvents,
{
    type Config = LockedDatagramQueuesConfig;
    type Handle = LockedDatagramQueuesHandle<Lc, K, S, H, E>;
    type Events = E;
    type Intake = H;
    type Remains = LockedDatagramQueuesRemains<S::Received>;
    type Received = S::Received;

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
                    waiting: BTreeMap::new(),
                    waiting_bytes: 0,
                    in_flight: BTreeMap::new(),
                    next_key: DatagramKey::FIRST,
                    end: None,
                    tickets: BTreeMap::new(),
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

    /// Under the queues' lock.
    fn supply_datagram<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        key: DatagramKey,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DatagramSummary, Idx>,
        Q: PacketPosition,
    {
        self.shared.supply::<W, Q, Idx>(key, packet)
    }

    fn on_frame_delivered(&mut self, summary: DatagramSummary) {
        self.shared.settle(summary.key, true);
    }

    fn on_frame_lost(&mut self, summary: DatagramSummary) {
        self.shared.settle(summary.key, false);
    }

    /// Published again through the intake.
    fn on_intent_unfulfilled<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        key: DatagramKey,
        cause: Unfulfilled,
    ) where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
    {
        self.shared.unfulfilled(key, cause);
    }

    /// Published through the intake.
    fn send_held<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        payload: Bytes,
        parameters: &Urgency,
        destination: &AnyActiveLinkPath,
    ) -> Result<DatagramKey, SendDatagramError<Lc>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
    {
        self.shared.send_held(payload, *parameters, *destination)
    }

    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<S::Received, LayerEndedError<Lc>>> {
        self.shared.poll_receive(cx)
    }

    fn limits(&self) -> DatagramFrameLimits {
        self.shared.limits()
    }

    fn dropped_datagrams(&self) -> u64 {
        lock(&self.shared.state).dropped
    }

    /// The intake's ticket tells whether it waits as too large; the
    /// publisher is not asked.
    fn ticket_state<Kp>(&self, _: &StrategyPublisherOf<I>, held: HeldDatagram<'_>) -> DatagramState
    where
        StrategyPublisherOf<I>: PublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = Kp>
            + IntentTicketChanges<Kp>,
    {
        let gone = || DatagramState::Withdrawn(held_datagram_gone(held.key()));
        match self.shared.held_ticket(held.key(), false) {
            // invariant: only a holder withdraws for itself, and it hands
            // its credential back as it does
            Some(cell) => cell.state().unwrap_or_else(gone),
            None => gone(),
        }
    }

    fn poll_ticket_settled(
        &mut self,
        held: HeldDatagram<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramSettlement> {
        match self.shared.held_ticket(held.key(), false) {
            Some(cell) => {
                let (progress, panicked) = cell.progress();
                progress.poll_settled(cx, panicked)
            }
            None => Poll::Ready(DatagramSettlement::Withdrawn(held_datagram_gone(
                held.key(),
            ))),
        }
    }

    fn withdraw_held<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        held: HeldDatagram<'_>,
    ) -> WithdrawReport
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
    {
        match self.shared.held_ticket(held.key(), true) {
            Some(cell) => cell.withdraw_for_holder(),
            None => {
                held_datagram_gone(held.key());
                WithdrawReport::Withdrawn
            }
        }
    }

    fn release_held(&mut self, held: HeldDatagram<'_>) {
        if self.shared.held_ticket(held.key(), true).is_none() {
            held_datagram_gone(held.key());
        }
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
            let in_flight = state.in_flight.values().filter_map(Weak::upgrade);
            state
                .waiting
                .values()
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

/// The capability of the locked queues with an independent share of the
/// send queue: the writer lends the layer once, when it is taken, and holds
/// the queues' shared state, where the handle of the intake they publish
/// through is, from then on, apart from the connection; one taken once the
/// layer ended reports the end. `Ie`, `Ic` and `Ir` are where the
/// connection handle's state is in the layer's lineage and in the
/// connection node's, and where version 1's part is in what the parts keep
/// after the end; `Iq` where the queues are in the layer's lineage.
impl<T, L, S, A, K, D, H, E, Ie, Ic, Ir, Iq> DetachedDatagrams<(Ie, Ic, Ir, Iq)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    K: IntentTicketWithdraw + IntentTicketState,
    D: DatagramSide,
    E: SharedEvents,
    DatagramQueuesOf<T, L>: DatagramQueues<
            crate::v1::CloseCauseOf<T, L>,
            SendTypes<T, L>,
            Handle = LockedDatagramQueuesHandle<crate::v1::CloseCauseOf<T, L>, K, D, H, E>,
        >,
    H: SendIntentHandle<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<DatagramQueuesOf<T, L>, Iq>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
{
    type SendShare = LockedDatagramSendShare<crate::v1::CloseCauseOf<T, L>, K, D, H, E>;

    fn datagram_writer_detached(&self) -> DatagramWriter<Self::SendShare, NoSendOptions> {
        let queue = self
            .lend_layer::<_, Ie, Ic, Ir>(|lineage, _| {
                SendQueueReach::Queues(lineage.get::<DatagramQueuesOf<T, L>, Iq>().handle().shared)
            })
            .unwrap_or_else(SendQueueReach::Ended);
        DatagramWriter::new(LockedDatagramSendShare { queue })
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
pub(in crate::datagram) mod tests;
