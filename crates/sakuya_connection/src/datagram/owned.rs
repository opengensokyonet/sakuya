//! The default queues of the established layer: both bounded queues held
//! directly by the queues, which are lent to whoever acts on them, and
//! reached only through the shared connection ([`OwnedDatagramQueues`]).
//!
//! The queues keep what [`LockedDatagramQueues`](super::locked::LockedDatagramQueues)
//! keeps under its lock, the datagrams received, the count of those
//! dropped, the datagrams sent and the end of the layer, as plain values:
//! whoever acts on them has them to themselves, the driver's side with a
//! frame received, a supply, an acknowledgment or a loss, the
//! application's with an operation of the capability through the shared
//! connection ([`shared`](super::shared)). Each of them is lent the send
//! strategy's publisher, publishes every intent through it
//! ([`PlacedPublisher`]), and the queues keep its key tickets
//! ([`PublishedTicketOf`]); whoever lent the publisher hands on what
//! changed there.
//!
//! - **Receiving.** As for the locked queues: a datagram received waits
//!   until the application reads it, within the bounds of the receive
//!   queue ([`DatagramQueueBounds`]), and what the queue drops is counted.
//! - **Sending.** Each datagram sent has one record, by its key
//!   ([`DatagramKey`]): its payload, its parameters and destination, the
//!   strategy's ticket while it waits, where it stands, and whether its
//!   ticket is held. The send queue's bounds are counted over the datagrams
//!   that wait. A record held by a ticket stays until the ticket's
//!   credential comes back; one not held goes once the datagram ended, or,
//!   written into a packet, once the packet was acknowledged or lost.
//! - **The end of the layer.** What was received is still read; then every
//!   read and send reports the end. The datagrams that wait are withdrawn
//!   as the layer ended, their intents withdrawn through the publisher the
//!   end is lent, and those in flight are lost. What was received and not read, the count
//!   of what was dropped and what the held tickets read go into the
//!   connection node ([`OwnedDatagramQueuesRemains`]).
//! - **A panic of the driver.** The end is only marked
//!   ([`DatagramQueues::driver_panicked`]): who waits to receive and who
//!   waits for a ticket to settle is woken; every receive and send then
//!   reports the end at once, a ticket of a datagram that waits reads it as
//!   withdrawn as the layer ended, one in flight as lost. Nothing is
//!   withdrawn and the strategy's tickets are left alone.

#[cfg(test)]
mod tests;

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use core::{
    fmt,
    task::{Context, Poll, Waker},
};

use bytes::{Buf, Bytes};
use sakuya_stream::{
    connection::{LayerEnd, LayerEndedError},
    send_options::{
        destination::{AnyActiveLinkPath, DestinationFallback, SendDestination, Unfulfilled},
        urgency::Urgency,
    },
};
use sakuya_wire::{
    datagram::{DatagramFrame, MaxDatagramFrameSize},
    v1::encryption_level::EncryptionLevel,
};

use super::{
    DatagramLayerRemains, DatagramOverflow, DatagramQueueBounds, DatagramQueues,
    DatagramQueuesFacts, DatagramSide,
    application::{DatagramFrameLimits, SendDatagramError},
    frame_len_with_length, peer_limits,
    send::{
        DatagramIntent, DatagramKey, DatagramSettlement, DatagramState, DatagramSummary,
        DatagramWithdrawCause, HeldDatagram, ProgressState, WithdrawReport, Withdrawal,
        held_datagram_gone, settlement_after_end, withdraw_report_after_end, write_datagram,
    },
};
use crate::{
    feedback::InjectSummary,
    send_strategy::{
        IntentPublisher, IntentTicketChanges, PlacedPublisher, PublishOutcome, PublishTo,
        SendIntent,
    },
    v1::{
        application_handles::connection::{keep_waker, wake_all},
        events::{DataLocation, DatagramDropped, NoEvents, SharedEvents},
        send_planning::{
            ComponentIntake, ComponentPublishing, HostSendStrategyTypes, PublishedTicketOf,
            StrategyPublisherForTicket, StrategyPublisherOf,
        },
    },
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// What [`OwnedDatagramQueues`] is configured with
/// (`OwnedDatagramQueuesConfig`): the bounds of each queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OwnedDatagramQueuesConfig {
    /// The bounds of the datagrams received.
    pub receive: DatagramQueueBounds,
    /// The bounds of the datagrams waiting to be sent.
    pub send: DatagramQueueBounds,
}

/// The default queues of the established layer: both queues held directly,
/// reached only through the shared connection; see the [module
/// documentation](self).
///
/// `Lc` is this endpoint's reason for closing, `K` the ticket of a
/// datagram's intent, which the send strategy's publisher gives, `S` the
/// side, which gives what a datagram received is, and `E` the handle the
/// events of the datagrams are given through, by default [`NoEvents`], as
/// for the locked queues. Datagrams are sent with an [`Urgency`], to any
/// active link path.
pub struct OwnedDatagramQueues<Lc, K, S: DatagramSide, E = NoEvents> {
    /// The largest payload the peer takes; `None` when it takes no
    /// DATAGRAM frames.
    peer_limit: Option<usize>,
    /// The peer's `max_datagram_frame_size`, counted as a frame length.
    peer_frame_limit: usize,
    config: OwnedDatagramQueuesConfig,
    /// The handle the events of the datagrams are given through.
    events: E,
    received: VecDeque<S::Received>,
    received_bytes: usize,
    dropped: u64,
    /// Who waits for a datagram received.
    receivers: Vec<Waker>,
    /// One record for each datagram sent that is still kept, by its key.
    datagrams: BTreeMap<DatagramKey, OwnedDatagram<K>>,
    /// How many of them wait to be sent, and their bytes of payload.
    waiting: usize,
    waiting_bytes: usize,
    /// The key the next datagram gets.
    next_key: DatagramKey,
    phase: Phase<Lc>,
}

/// The default queues of the established layer.
pub type DefaultDatagramQueues<Lc, K, S, E = NoEvents> = OwnedDatagramQueues<Lc, K, S, E>;

/// Whether the layer runs, ended, or ended as the driver panicked.
#[derive(Debug)]
enum Phase<Lc> {
    /// It runs.
    Running,
    /// It ended as told.
    Ended(LayerEnd<Lc>),
    /// The driver panicked: only marked, with the rest left as the panic
    /// left it.
    Panicked(LayerEnd<Lc>),
}

/// One datagram sent, as the queues keep it (`OwnedDatagram`), sent to the
/// destination `D`.
struct OwnedDatagram<K, D = AnyActiveLinkPath> {
    payload: Bytes,
    parameters: Urgency,
    destination: D,
    /// The strategy's ticket of its intent, while it waits.
    ticket: Option<K>,
    progress: ProgressState,
    /// Whether its ticket is held through the shared connection, until the
    /// ticket's credential comes back.
    held: bool,
}

impl<K, D> OwnedDatagram<K, D> {
    /// The intent of the datagram of `key`.
    fn intent(&self, key: DatagramKey) -> DatagramIntent<Urgency> {
        DatagramIntent::new(key, self.payload.len(), self.parameters)
    }

    /// Whether the queues forget it: no ticket holds it, and nothing more
    /// can happen to it that a holder would hear of.
    fn forgotten(&self) -> bool {
        !self.held && !self.progress.is_open()
    }

    /// Withdraw the datagram as `withdrawal` says, if it waits, with its
    /// strategy's ticket through `publish`: whether it waited.
    fn withdraw<H>(&mut self, withdrawal: Withdrawal, publish: &mut H) -> bool
    where
        H: IntentPublisher<DatagramIntent<Urgency>, AnyActiveLinkPath, Ticket = K>,
    {
        if !self.progress.is_waiting() {
            return false;
        }
        self.progress.withdraw(withdrawal);
        if let Some(ticket) = self.ticket.take() {
            publish.withdraw(ticket);
        }
        true
    }

    /// The intent of the datagram of `key` was not fulfilled for `cause`:
    /// the strategy ended its ticket, which goes through `publish`; while
    /// the destination degrades, it is published again to what it gives,
    /// and once it has nothing left, the datagram is withdrawn. Whether it
    /// still waits.
    fn unfulfilled<H>(&mut self, key: DatagramKey, cause: Unfulfilled, publish: &mut H) -> bool
    where
        D: SendDestination<Current = AnyActiveLinkPath>,
        H: IntentPublisher<DatagramIntent<Urgency>, AnyActiveLinkPath, Ticket = K>,
    {
        if !self.progress.is_waiting() {
            return false;
        }
        if let Some(ended) = self.ticket.take() {
            // the strategy ended it: withdrawing it changes nothing more
            publish.withdraw(ended);
        }
        match self.destination.on_unfulfilled(cause) {
            DestinationFallback::Degraded => {
                let intent = self.intent(key);
                self.ticket = Some(publish.publish_to(intent, self.destination.current()));
                true
            }
            DestinationFallback::Exhausted => {
                self.progress.withdraw(Withdrawal::Cause(
                    DatagramWithdrawCause::DestinationExhausted,
                ));
                false
            }
        }
    }
}

/// What the queues of one layer leave once it ended
/// (`OwnedDatagramQueuesRemains`): the datagrams received that the
/// application has not read, of the side's type `R`, how many were dropped
/// because the receive queue was full, and what each ticket held through
/// the shared connection reads, by its datagram's key.
pub struct OwnedDatagramQueuesRemains<R> {
    received: VecDeque<R>,
    dropped: u64,
    tickets: BTreeMap<DatagramKey, DatagramState>,
}

impl<R> fmt::Debug for OwnedDatagramQueuesRemains<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedDatagramQueuesRemains")
            .field("received", &self.received.len())
            .field("dropped", &self.dropped)
            .finish_non_exhaustive()
    }
}

/// What each held ticket reads is as the layer's end left it.
impl<R> DatagramLayerRemains for OwnedDatagramQueuesRemains<R> {
    type Received = R;

    fn pop_received(&mut self) -> Option<R> {
        self.received.pop_front()
    }

    fn dropped(&self) -> u64 {
        self.dropped
    }

    fn ticket_state(&self, key: DatagramKey) -> Option<DatagramState> {
        self.tickets.get(&key).copied()
    }

    fn ticket_settlement(&self, key: DatagramKey) -> Option<DatagramSettlement> {
        self.ticket_state(key).map(settlement_after_end)
    }

    fn take_ticket(&mut self, key: DatagramKey) -> Option<WithdrawReport> {
        self.tickets.remove(&key).map(withdraw_report_after_end)
    }
}

/// The kind of [`OwnedDatagramQueues`].
#[derive(Debug)]
pub struct OwnedDatagramQueuesFamily;

impl super::DatagramQueuesFamily for OwnedDatagramQueuesFamily {
    type Config = OwnedDatagramQueuesConfig;
    type Remains<S: DatagramSide> = OwnedDatagramQueuesRemains<S::Received>;
    type Queues<
        Lc,
        I: ComponentPublishing<Self, DatagramIntent<Urgency>>,
        S: DatagramSide,
        E: SharedEvents + Clone + 'static,
    > = OwnedDatagramQueues<
        Lc,
        <I as ComponentPublishing<Self, DatagramIntent<Urgency>>>::Ticket,
        S,
        E,
    >;
}

/// The queues are held only through the shared connection: they publish
/// through the strategy's publisher they are lent, and keep that
/// publisher's tickets, for any strategy types.
impl<I> ComponentPublishing<OwnedDatagramQueuesFamily, DatagramIntent<Urgency>> for I
where
    I: HostSendStrategyTypes,
    StrategyPublisherOf<I>: PublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
{
    type Ticket = PublishedTicketOf<I, DatagramIntent<Urgency>>;
    type Intake = ();
}

/// They ask the core for nothing; `Idx` is where the publisher takes the
/// datagram intents.
impl<I, Idx> ComponentIntake<OwnedDatagramQueuesFamily, DatagramIntent<Urgency>, Idx> for I
where
    I: HostSendStrategyTypes,
    DatagramIntent<Urgency>: SendIntent,
    StrategyPublisherOf<I>: PublishTo<DatagramIntent<Urgency>, AnyActiveLinkPath, Idx>,
{
    fn intake(_: &mut I::Strategy) -> Self::Intake {}
}

impl<Lc, K, S: DatagramSide, E> fmt::Debug for OwnedDatagramQueues<Lc, K, S, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedDatagramQueues")
            .field("config", &self.config)
            .field("datagrams", &self.datagrams.len())
            .finish_non_exhaustive()
    }
}

/// Everything the queues do, over whatever they publish through, `H`: the
/// strategy's publisher placed for the datagram intents when they are lent
/// one ([`DatagramQueues`]), or anything else that publishes them.
impl<Lc, K, S, E> OwnedDatagramQueues<Lc, K, S, E>
where
    S: DatagramSide,
    E: SharedEvents,
{
    /// The queues of a layer, as [`DatagramQueues::new`] makes them.
    fn made(facts: DatagramQueuesFacts, config: OwnedDatagramQueuesConfig, events: E) -> Self {
        let (peer_limit, peer_frame_limit) = peer_limits(facts.peer);
        Self {
            peer_limit,
            peer_frame_limit,
            config,
            events,
            received: VecDeque::new(),
            received_bytes: 0,
            dropped: 0,
            receivers: Vec::new(),
            datagrams: BTreeMap::new(),
            waiting: 0,
            waiting_bytes: 0,
            next_key: DatagramKey::FIRST,
            phase: Phase::Running,
        }
    }

    /// The handle for the events of the datagrams, when they are recorded.
    #[inline(always)]
    fn events(&self) -> Option<&E> {
        (E::ENABLED && self.events.enabled()).then_some(&self.events)
    }

    /// A datagram of `length` bytes of payload was dropped as `dropped`
    /// says.
    fn dropped(&self, length: usize, dropped: DatagramDropped) {
        if let Some(events) = self.events() {
            events.datagram_dropped(length, dropped);
        }
    }

    /// Whether the driver panicked.
    fn panicked(&self) -> bool {
        matches!(self.phase, Phase::Panicked(_))
    }

    /// The datagram of `key` no longer waits: it leaves the count of those
    /// that wait, and is forgotten if nothing holds it.
    fn left_waiting(&mut self, key: DatagramKey) {
        let Some(datagram) = self.datagrams.get(&key) else {
            return;
        };
        self.waiting -= 1;
        self.waiting_bytes -= datagram.payload.len();
        self.forget_if_done(key);
    }

    /// Forget the datagram of `key` if nothing holds it and nothing more
    /// can happen to it.
    fn forget_if_done(&mut self, key: DatagramKey) {
        if self
            .datagrams
            .get(&key)
            .is_some_and(OwnedDatagram::forgotten)
        {
            self.datagrams.remove(&key);
        }
    }

    /// The record of the held datagram of `held`; `None` once its
    /// credential came back.
    fn held(&self, held: HeldDatagram<'_>) -> Option<&OwnedDatagram<K>> {
        self.datagrams
            .get(&held.key())
            .filter(|datagram| datagram.held)
    }

    // ---- receiving ----

    /// A datagram of `level` and `frame` arrived: kept, or dropped as the
    /// receive queue's bounds say. Once the layer ended, it is not taken.
    fn receive(&mut self, level: EncryptionLevel, frame: DatagramFrame<Bytes>) {
        if !matches!(self.phase, Phase::Running) {
            return;
        }
        let bounds = self.config.receive;
        let datagram = S::received(level, frame.into_data());
        let len = datagram.remaining();
        if len > bounds.bytes {
            // larger than the whole queue: dropped, the others kept
            self.dropped += 1;
            self.dropped(len, DatagramDropped::ReceiveQueueFull);
            return;
        }
        while self.received.len() >= bounds.datagrams.get()
            || self.received_bytes.saturating_add(len) > bounds.bytes
        {
            let oldest = match bounds.overflow {
                DatagramOverflow::DropOldest => self.received.pop_front(),
                DatagramOverflow::RejectNew => None,
            };
            let Some(oldest) = oldest else {
                // the new one is dropped
                self.dropped += 1;
                self.dropped(len, DatagramDropped::ReceiveQueueFull);
                return;
            };
            self.received_bytes -= oldest.remaining();
            self.dropped += 1;
            self.dropped(oldest.remaining(), DatagramDropped::ReceiveQueueFull);
        }
        self.received_bytes += len;
        self.received.push_back(datagram);
        wake_all(&mut self.receivers);
    }

    /// The next datagram received, or the layer's end once none is left;
    /// at once once the driver panicked.
    fn poll_receive_now(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<S::Received, LayerEndedError<Lc>>> {
        if let Phase::Panicked(end) = &self.phase {
            return Poll::Ready(Err(LayerEndedError::new(end.clone())));
        }
        if let Some(datagram) = self.received.pop_front() {
            self.received_bytes -= datagram.remaining();
            if let Some(events) = self.events() {
                let len = datagram.remaining();
                events.datagram_data_moved(len, DataLocation::Transport, DataLocation::Application);
            }
            return Poll::Ready(Ok(datagram));
        }
        match &self.phase {
            Phase::Ended(end) | Phase::Panicked(end) => {
                Poll::Ready(Err(LayerEndedError::new(end.clone())))
            }
            Phase::Running => {
                keep_waker(&mut self.receivers, cx.waker());
                Poll::Pending
            }
        }
    }

    // ---- sending ----

    /// Take `payload` into the send queue for a holder, publishing its
    /// intent through `publish` with `parameters` to `destination`: its key.
    fn send_held_through<H>(
        &mut self,
        publish: &mut H,
        payload: Bytes,
        parameters: Urgency,
        destination: AnyActiveLinkPath,
    ) -> Result<DatagramKey, SendDatagramError<Lc>>
    where
        H: IntentPublisher<DatagramIntent<Urgency>, AnyActiveLinkPath, Ticket = K>,
    {
        let Some(limit) = self.peer_limit else {
            return Err(SendDatagramError::NotSupportedByPeer);
        };
        let len = payload.len();
        if frame_len_with_length(len) > self.peer_frame_limit {
            return Err(SendDatagramError::TooLarge { limit });
        }
        if let Phase::Ended(end) | Phase::Panicked(end) = &self.phase {
            return Err(LayerEndedError::new(end.clone()).into());
        }
        let bounds = self.config.send;
        if len > bounds.bytes {
            // larger than the whole queue: no room can be made for it
            return Err(SendDatagramError::QueueFull);
        }
        while self.waiting >= bounds.datagrams.get()
            || self.waiting_bytes.saturating_add(len) > bounds.bytes
        {
            if bounds.overflow == DatagramOverflow::RejectNew {
                return Err(SendDatagramError::QueueFull);
            }
            let oldest = self
                .datagrams
                .iter_mut()
                .find(|(_, datagram)| datagram.progress.is_waiting());
            let Some((&key, oldest)) = oldest else {
                // invariant: the count is of the records that wait
                debug_assert!(false, "{} datagrams counted as waiting", self.waiting);
                return Err(SendDatagramError::QueueFull);
            };
            oldest.withdraw(
                Withdrawal::Cause(DatagramWithdrawCause::DroppedOldest),
                publish,
            );
            let dropped = oldest.payload.len();
            self.dropped(dropped, DatagramDropped::SendQueueFull);
            self.left_waiting(key);
        }
        let key = self.next_key;
        self.next_key = key.next();
        let ticket = publish.publish_to(
            DatagramIntent::new(key, len, parameters),
            destination.current(),
        );
        self.datagrams.insert(
            key,
            OwnedDatagram {
                payload,
                parameters,
                destination,
                ticket: Some(ticket),
                progress: ProgressState::new(),
                held: true,
            },
        );
        self.waiting += 1;
        self.waiting_bytes += len;
        if let Some(events) = self.events() {
            events.datagram_data_moved(len, DataLocation::Application, DataLocation::Transport);
        }
        Ok(key)
    }

    /// Write the datagram of `key`, if it waits and its frame fits; its
    /// ticket goes through `publish` as written.
    fn supply_through<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        key: DatagramKey,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<DatagramIntent<Urgency>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DatagramSummary, Idx>,
        Q: PacketPosition,
    {
        let Some(datagram) = self.datagrams.get_mut(&key) else {
            return Supplied::Open(packet);
        };
        let progress = &mut datagram.progress;
        let (supplied, written) = write_datagram(
            datagram.payload.clone(),
            packet,
            DatagramSummary { key },
            || progress.start_writing(),
        );
        if written {
            // the plan that wrote it consumes its intent
            if let Some(ticket) = datagram.ticket.take() {
                publish.release_written(ticket);
            }
            self.left_waiting(key);
        }
        supplied
    }

    /// The packet the datagram of `key` was written into was acknowledged,
    /// or, if `delivered` is false, declared lost.
    fn settle(&mut self, key: DatagramKey, delivered: bool) {
        let Some(datagram) = self.datagrams.get_mut(&key) else {
            return;
        };
        datagram.progress.settle(delivered);
        self.forget_if_done(key);
    }

    /// The intent of the datagram of `key` was not fulfilled for `cause`;
    /// its destination decides now.
    fn on_intent_unfulfilled_through<H>(
        &mut self,
        publish: &mut H,
        key: DatagramKey,
        cause: Unfulfilled,
    ) where
        H: IntentPublisher<DatagramIntent<Urgency>, AnyActiveLinkPath, Ticket = K>,
    {
        let Some(datagram) = self.datagrams.get_mut(&key) else {
            return;
        };
        let waited = datagram.progress.is_waiting();
        if !datagram.unfulfilled(key, cause, publish) && waited {
            self.left_waiting(key);
        }
    }

    // ---- the holders through the shared connection ----

    /// Where the datagram of `held` stands; one that waits is too large for
    /// now when `too_large` says so of its ticket.
    fn held_state(
        &self,
        held: HeldDatagram<'_>,
        too_large: impl FnOnce(&K) -> bool,
    ) -> DatagramState {
        let gone = || DatagramState::Withdrawn(held_datagram_gone(held.key()));
        let Some(datagram) = self.held(held) else {
            return gone();
        };
        // invariant: a holder withdraws only as it hands its credential back
        match datagram.progress.state(self.panicked()) {
            Some(DatagramState::Waiting) if datagram.ticket.as_ref().is_some_and(too_large) => {
                DatagramState::WaitingTooLarge
            }
            Some(state) => state,
            None => gone(),
        }
    }

    /// The settlement of the datagram of `held`, or `Pending` with the
    /// waker of `cx` kept.
    fn poll_held_settled(
        &mut self,
        held: HeldDatagram<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramSettlement> {
        let panicked = self.panicked();
        match self
            .datagrams
            .get_mut(&held.key())
            .filter(|datagram| datagram.held)
        {
            Some(datagram) => datagram.progress.poll_settled(cx, panicked),
            None => Poll::Ready(DatagramSettlement::Withdrawn(held_datagram_gone(
                held.key(),
            ))),
        }
    }

    /// The holder of `held` hands its credential back and withdraws the
    /// datagram through `publish`: what withdrawing reports. Once the
    /// driver panicked, only what that would report, with nothing
    /// withdrawn.
    fn withdraw_held_through<H>(
        &mut self,
        publish: &mut H,
        held: HeldDatagram<'_>,
    ) -> WithdrawReport
    where
        H: IntentPublisher<DatagramIntent<Urgency>, AnyActiveLinkPath, Ticket = K>,
    {
        let key = held.key();
        let panicked = self.panicked();
        let Some(datagram) = self
            .datagrams
            .get_mut(&key)
            .filter(|datagram| datagram.held)
        else {
            held_datagram_gone(key);
            return WithdrawReport::Withdrawn;
        };
        datagram.held = false;
        let report = datagram.progress.withdraw_report();
        if !panicked && datagram.withdraw(Withdrawal::Holder, publish) {
            self.left_waiting(key);
        } else {
            self.forget_if_done(key);
        }
        report
    }

    /// The holder of `held` hands its credential back without withdrawing
    /// the datagram.
    fn release_held_now(&mut self, held: HeldDatagram<'_>) {
        let key = held.key();
        match self
            .datagrams
            .get_mut(&key)
            .filter(|datagram| datagram.held)
        {
            Some(datagram) => {
                datagram.held = false;
                self.forget_if_done(key);
            }
            None => {
                held_datagram_gone(key);
            }
        }
    }

    // ---- the end ----

    /// The peer's `max_datagram_frame_size` of this handshake, `peer`:
    /// what a datagram sent from now on is held to.
    fn peer_transport_parameters_known_now(&mut self, peer: MaxDatagramFrameSize) {
        if !matches!(self.phase, Phase::Running) {
            return;
        }
        (self.peer_limit, self.peer_frame_limit) = peer_limits(peer);
    }

    /// The layer ended as `end`: the datagrams that wait are withdrawn as
    /// it ended, their intents through `publish`, those in flight are lost,
    /// and who waits hears of it.
    fn layer_ended_now<H>(&mut self, publish: &mut H, end: LayerEnd<Lc>)
    where
        H: IntentPublisher<DatagramIntent<Urgency>, AnyActiveLinkPath, Ticket = K>,
    {
        if !matches!(self.phase, Phase::Running) {
            return;
        }
        self.phase = Phase::Ended(end);
        wake_all(&mut self.receivers);
        for datagram in self.datagrams.values_mut() {
            datagram.withdraw(
                Withdrawal::Cause(DatagramWithdrawCause::LayerEnded),
                publish,
            );
            // nothing settles a packet in flight after the layer's end
            datagram.progress.settle(false);
        }
        self.waiting = 0;
        self.waiting_bytes = 0;
        self.datagrams.retain(|_, datagram| !datagram.forgotten());
    }

    /// The driver panicked: only mark the end and wake who waits.
    fn driver_panicked_now(&mut self, end: LayerEnd<Lc>) {
        if !matches!(self.phase, Phase::Running) {
            return;
        }
        self.phase = Phase::Panicked(end);
        wake_all(&mut self.receivers);
        for datagram in self.datagrams.values_mut() {
            datagram.progress.wake_waiters();
        }
    }

    /// What the queues leave once the layer ended: what was received and
    /// not read, the count of what was dropped, and what the held tickets
    /// read.
    fn remains_now(&mut self) -> OwnedDatagramQueuesRemains<S::Received> {
        self.received_bytes = 0;
        let panicked = self.panicked();
        let tickets = core::mem::take(&mut self.datagrams)
            .into_iter()
            .filter(|(_, datagram)| datagram.held)
            .filter_map(|(key, datagram)| Some((key, datagram.progress.state(panicked)?)))
            .collect();
        OwnedDatagramQueuesRemains {
            received: core::mem::take(&mut self.received),
            dropped: self.dropped,
            tickets,
        }
    }

    fn limits_now(&self) -> DatagramFrameLimits {
        let peer = self.peer_limit.unwrap_or(0);
        DatagramFrameLimits {
            guaranteed: peer.min(super::GUARANTEED_PAYLOAD),
            peer,
        }
    }
}

/// The publisher `publish` placed for the datagram intents at `Ij`.
fn placed<R, Ij>(publish: &mut R) -> PlacedPublisher<'_, R, DatagramIntent<Urgency>, Ij> {
    PlacedPublisher::new(publish)
}

/// Everything the queues publish goes through the strategy's publisher
/// they are lent, placed for the datagram intents at `Ij`; the tickets they
/// keep are the publisher's, which the publisher tells too large for now.
impl<Lc, I, S, E> DatagramQueues<Lc, I>
    for OwnedDatagramQueues<Lc, PublishedTicketOf<I, DatagramIntent<Urgency>>, S, E>
where
    I: HostSendStrategyTypes,
    StrategyPublisherOf<I>: PublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath>,
    S: DatagramSide,
    E: SharedEvents,
{
    type Config = OwnedDatagramQueuesConfig;
    /// Nothing of them is held apart from the connection.
    type Handle = ();
    type Events = E;
    type Remains = OwnedDatagramQueuesRemains<S::Received>;
    type Intake = ();
    type Received = S::Received;

    fn new(
        facts: DatagramQueuesFacts,
        config: OwnedDatagramQueuesConfig,
        events: E,
        (): (),
    ) -> Self {
        Self::made(facts, config, events)
    }

    fn handle(&self) {}

    fn on_datagram_frame(&mut self, level: EncryptionLevel, frame: DatagramFrame<Bytes>) {
        self.receive(level, frame);
    }

    fn peer_transport_parameters_known(&mut self, peer: MaxDatagramFrameSize) {
        self.peer_transport_parameters_known_now(peer);
    }

    fn layer_ended<Ij, Kp>(&mut self, publish: &mut StrategyPublisherOf<I>, end: LayerEnd<Lc>)
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
    {
        self.layer_ended_now(&mut placed::<_, Ij>(publish), end);
    }

    fn driver_panicked(&mut self, end: LayerEnd<Lc>) {
        self.driver_panicked_now(end);
    }

    fn remains(&mut self) -> OwnedDatagramQueuesRemains<S::Received> {
        self.remains_now()
    }

    fn supply_datagram<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        key: DatagramKey,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DatagramSummary, Idx>,
        Q: PacketPosition,
    {
        self.supply_through::<_, W, Q, Idx>(&mut placed::<_, Ij>(publish), key, packet)
    }

    fn on_frame_delivered(&mut self, summary: DatagramSummary) {
        self.settle(summary.key, true);
    }

    fn on_frame_lost(&mut self, summary: DatagramSummary) {
        self.settle(summary.key, false);
    }

    fn on_intent_unfulfilled<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        key: DatagramKey,
        cause: Unfulfilled,
    ) where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
    {
        self.on_intent_unfulfilled_through(&mut placed::<_, Ij>(publish), key, cause);
    }

    fn send_held<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        payload: Bytes,
        parameters: &Urgency,
        destination: &AnyActiveLinkPath,
    ) -> Result<DatagramKey, SendDatagramError<Lc>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
    {
        self.send_held_through(
            &mut placed::<_, Ij>(publish),
            payload,
            *parameters,
            *destination,
        )
    }

    fn poll_receive(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<S::Received, LayerEndedError<Lc>>> {
        self.poll_receive_now(cx)
    }

    fn limits(&self) -> DatagramFrameLimits {
        self.limits_now()
    }

    fn dropped_datagrams(&self) -> u64 {
        self.dropped
    }

    /// The publisher tells whether the datagram's key ticket waits as too
    /// large.
    fn ticket_state<Kp>(
        &self,
        publish: &StrategyPublisherOf<I>,
        held: HeldDatagram<'_>,
    ) -> DatagramState
    where
        StrategyPublisherOf<I>: PublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = Kp>
            + IntentTicketChanges<Kp>,
    {
        self.held_state(held, |ticket| publish.waits_too_large(ticket))
    }

    fn poll_ticket_settled(
        &mut self,
        held: HeldDatagram<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramSettlement> {
        self.poll_held_settled(held, cx)
    }

    fn withdraw_held<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: HeldDatagram<'_>,
    ) -> WithdrawReport
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<DatagramIntent<Urgency>, Ij, Kp>,
    {
        self.withdraw_held_through(&mut placed::<_, Ij>(publish), held)
    }

    fn release_held(&mut self, held: HeldDatagram<'_>) {
        self.release_held_now(held);
    }
}
