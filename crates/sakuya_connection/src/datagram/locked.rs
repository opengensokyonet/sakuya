//! The default queues of the established layer: one lock over both bounded
//! queues, which the connection and the application's handles share
//! ([`LockedDatagramQueues`]).
//!
//! - **Receiving.** A datagram received waits until the application reads
//!   it; the queue holds at most so many datagrams and so many bytes of
//!   payload ([`DatagramQueueBounds`]). When one more comes, the queue
//!   drops the oldest ones or the new one, as it is configured
//!   ([`DatagramOverflow`]), and counts what it dropped
//!   ([`LockedDatagramQueuesHandle::dropped_datagrams`]). Receiving never
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
//!
//! Lock order: the queues' lock comes first; a datagram's progress and its
//! route are taken under it, one at a time, and publishing or withdrawing an
//! intent takes the send strategy's lock under it. The DATAGRAM frame
//! source takes no lock of the queues: it writes from the intent, and the
//! queue counts a datagram written as gone the next time it looks.

use core::{
    fmt,
    future::{Future, poll_fn},
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use bytes::{Buf, Bytes};
use sakuya_stream::{
    connection::{LayerEnd, LayerEndedError},
    send_options::{
        destination::{AnyActiveLinkPath, SendDestination},
        urgency::Urgency,
    },
};
use sakuya_wire::{datagram::DatagramFrame, v1::encryption_level::EncryptionLevel};

use super::{
    DatagramOverflow, DatagramQueues, DatagramQueuesFacts, DatagramSide,
    application::{
        DatagramFrameLimits, DatagramSend, DatagramWriter, Datagrams, SendDatagramError,
    },
    frame_len_with_length, payload_limit,
    send::{
        DatagramCell, DatagramIntent, DatagramProgress, DatagramTicket, DatagramWithdrawCause,
        Withdrawal,
    },
};
use crate::{
    send_strategy::{
        IntentTicketWithdraw, PublishOutcome, SendIntentHandle, SendIntentIntake, SharedPublishTo,
    },
    v1::application_handles::connection::{keep_waker, lock, wake_all},
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
/// what a datagram received is. Datagrams are sent with an [`Urgency`], to
/// any active link path.
pub struct LockedDatagramQueues<Lc, K, S: DatagramSide> {
    shared: Arc<QueuesShare<Lc, K, S>>,
}

/// The default queues of the established layer.
pub type DefaultDatagramQueues<Lc, K, S> = LockedDatagramQueues<Lc, K, S>;

/// A datagram to send, as the send queue holds it.
type SendCell<K> = DatagramCell<K, AnyActiveLinkPath, Urgency>;

/// What the queues and their handles share.
struct QueuesShare<Lc, K, S: DatagramSide> {
    /// The largest payload the peer takes; `None` when it takes no
    /// DATAGRAM frames.
    peer_limit: Option<usize>,
    /// The peer's `max_datagram_frame_size`, counted as a frame length.
    peer_frame_limit: usize,
    config: LockedDatagramQueuesConfig,
    state: Mutex<QueuesState<Lc, K, S::Received>>,
}

struct QueuesState<Lc, K, R> {
    received: VecDeque<R>,
    received_bytes: usize,
    dropped: u64,
    /// Who waits for a datagram received.
    receivers: Vec<Waker>,
    waiting: VecDeque<Arc<SendCell<K>>>,
    waiting_bytes: usize,
    /// How the layer ended, once it did.
    end: Option<LayerEnd<Lc>>,
}

impl<Lc, K, S: DatagramSide> fmt::Debug for LockedDatagramQueues<Lc, K, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedDatagramQueues")
            .field("config", &self.shared.config)
            .finish_non_exhaustive()
    }
}

impl<Lc, K: IntentTicketWithdraw, S: DatagramSide> QueuesShare<Lc, K, S> {
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
                return;
            };
            state.received_bytes -= oldest.remaining();
            state.dropped += 1;
        }
        state.received_bytes += len;
        state.received.push_back(datagram);
        wake_all(&mut state.receivers);
    }

    /// The next datagram received, or the layer's end once none is left.
    fn poll_receive(&self, cx: &mut Context<'_>) -> Poll<Result<S::Received, LayerEndedError<Lc>>> {
        let mut state = lock(&self.state);
        if let Some(datagram) = state.received.pop_front() {
            state.received_bytes -= datagram.remaining();
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
        if let Some(end) = &state.end {
            return Err(LayerEndedError::new(end.clone()).into());
        }
        if len > bounds.bytes {
            // larger than the whole queue: no room can be made for it
            return Err(SendDatagramError::QueueFull);
        }
        // what was written or withdrawn since leaves the queue; what was not
        // fulfilled goes on as its destination says
        let mut gone = 0;
        state.waiting.retain(|cell| {
            cell.resolve_unfulfilled(publish);
            let waiting = cell.is_waiting();
            if !waiting {
                gone += cell.len();
            }
            waiting
        });
        state.waiting_bytes -= gone;
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
            // written meanwhile, it leaves the queue all the same
            oldest.withdraw(Withdrawal::Cause(DatagramWithdrawCause::DroppedOldest));
        }
        let progress = DatagramProgress::new();
        let intent = DatagramIntent::new(payload, parameters, progress);
        let ticket = publish.publish_to(intent.clone(), destination.current());
        let cell = DatagramCell::new(intent, ticket, destination);
        state.waiting_bytes += len;
        state.waiting.push_back(Arc::clone(&cell));
        Ok(DatagramTicket::new(cell))
    }

    fn limits(&self) -> DatagramFrameLimits {
        let limit = self.peer_limit.unwrap_or(0);
        DatagramFrameLimits {
            everywhere: limit,
            somewhere: limit,
        }
    }
}

impl<Lc, K, S> DatagramQueues<Lc> for LockedDatagramQueues<Lc, K, S>
where
    K: IntentTicketWithdraw,
    S: DatagramSide,
{
    type Config = LockedDatagramQueuesConfig;
    type Handle<N: Clone> = LockedDatagramQueuesHandle<Lc, K, S, N>;

    fn new(facts: DatagramQueuesFacts, config: LockedDatagramQueuesConfig) -> Self {
        let peer_frame_limit = usize::try_from(facts.peer.get().get()).unwrap_or(usize::MAX);
        let peer_limit = (peer_frame_limit > 0).then(|| payload_limit(facts.peer).unwrap_or(0));
        Self {
            shared: Arc::new(QueuesShare {
                peer_limit,
                peer_frame_limit,
                config,
                state: Mutex::new(QueuesState {
                    received: VecDeque::new(),
                    received_bytes: 0,
                    dropped: 0,
                    receivers: Vec::new(),
                    waiting: VecDeque::new(),
                    waiting_bytes: 0,
                    end: None,
                }),
            }),
        }
    }

    fn handle<N: Clone>(&self, intake: N) -> LockedDatagramQueuesHandle<Lc, K, S, N> {
        LockedDatagramQueuesHandle {
            shared: Arc::clone(&self.shared),
            intake,
        }
    }

    fn on_datagram_frame(&mut self, level: EncryptionLevel, frame: DatagramFrame<Bytes>) {
        self.shared.receive(level, frame);
    }

    fn layer_ended(&mut self, end: LayerEnd<Lc>) {
        self.shared.end(end);
    }
}

/// The handle of a [`LockedDatagramQueues`] (`LockedDatagramQueuesHandle`):
/// it shares the queues' state, and publishes through the send strategy's
/// intake `N`. A clone is the same handle.
pub struct LockedDatagramQueuesHandle<Lc, K, S: DatagramSide, N> {
    shared: Arc<QueuesShare<Lc, K, S>>,
    intake: N,
}

impl<Lc, K, S: DatagramSide, N: Clone> Clone for LockedDatagramQueuesHandle<Lc, K, S, N> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            intake: self.intake.clone(),
        }
    }
}

impl<Lc, K, S: DatagramSide, N> fmt::Debug for LockedDatagramQueuesHandle<Lc, K, S, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedDatagramQueuesHandle")
            .finish_non_exhaustive()
    }
}

impl<Lc, K, S: DatagramSide, N> LockedDatagramQueuesHandle<Lc, K, S, N> {
    /// How many datagrams received were dropped because the receive queue
    /// was full; it only grows.
    pub fn dropped_datagrams(&self) -> u64 {
        lock(&self.shared.state).dropped
    }
}

/// The capability of the queues: the writer publishes through the intake's
/// handle for the datagram intents at the place `I`.
impl<Lc, K, S, N, I> Datagrams<I> for LockedDatagramQueuesHandle<Lc, K, S, N>
where
    K: IntentTicketWithdraw,
    S: DatagramSide,
    N: SendIntentIntake<AnyActiveLinkPath>
        + SharedPublishTo<DatagramIntent<Urgency>, AnyActiveLinkPath, I>
        + PublishOutcome<DatagramIntent<Urgency>, AnyActiveLinkPath, Outcome = K>,
{
    type Received = S::Received;
    type SendShare = LockedDatagramSendShare<Lc, K, S, N::Handle<DatagramIntent<Urgency>, I>>;
    type CloseCause = Lc;

    fn datagram_writer(
        &self,
    ) -> DatagramWriter<Self::SendShare, sakuya_stream::send_options::NoSendOptions> {
        DatagramWriter::new(LockedDatagramSendShare {
            shared: Arc::clone(&self.shared),
            publish: self.intake.handle::<DatagramIntent<Urgency>, I>(),
        })
    }

    fn recv_datagram(&self) -> impl Future<Output = Result<S::Received, LayerEndedError<Lc>>> {
        let shared = &self.shared;
        poll_fn(move |cx| shared.poll_receive(cx))
    }
}

/// This side's share of the send queue of a [`LockedDatagramQueues`]
/// (`LockedDatagramSendShare`), with the handle `H` it publishes through.
pub struct LockedDatagramSendShare<Lc, K, S: DatagramSide, H> {
    shared: Arc<QueuesShare<Lc, K, S>>,
    publish: H,
}

impl<Lc, K, S: DatagramSide, H: Clone> Clone for LockedDatagramSendShare<Lc, K, S, H> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            publish: self.publish.clone(),
        }
    }
}

impl<Lc, K, S: DatagramSide, H> fmt::Debug for LockedDatagramSendShare<Lc, K, S, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedDatagramSendShare")
            .finish_non_exhaustive()
    }
}

/// Datagrams are sent with an urgency, to any active link path.
impl<Lc, K, S, H> DatagramSend for LockedDatagramSendShare<Lc, K, S, H>
where
    K: IntentTicketWithdraw,
    S: DatagramSide,
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
        self.shared
            .send(&self.publish, payload, *parameters, *destination)
    }

    fn datagram_limits(&self) -> DatagramFrameLimits {
        self.shared.limits()
    }
}

#[cfg(test)]
mod tests;
