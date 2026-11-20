//! The stream set whose capabilities can also be held apart from the
//! connection: the streams under one lock, each part of a stream under a
//! lock of its own ([`LockedStreamSet`]).
//!
//! One lock, the set's, holds the streams' identity
//! ([`StreamIdLedger`](sakuya_stream::stream_id_ledger::StreamIdLedger)),
//! the table of the sending parts and the table of the receiving parts, the
//! queues of the streams the peer opened that the application has not
//! accepted yet, the end of the layer, and what the connection sends about
//! the streams' identity and its own send credit: the MAX_STREAMS and
//! STREAMS_BLOCKED frames of each directionality and the DATA_BLOCKED
//! frame, with the tickets of their intents. Each part of each stream is
//! under a lock of its own ([`LockedStreamEnd`]), together with the tickets
//! of the intents of its frames: one operation on the part has it to
//! itself. The connection's receive flow controller is under a third kind of
//! lock, with the ticket of the MAX_DATA intent, as the application's reads
//! update it too; the connection's send flow controller is shared by the
//! sending parts and takes no lock.
//!
//! The order of the locks: the set's lock and a part's lock are never held
//! together: a part is found or made under the set's lock, the set's lock is
//! let go, and then the part's lock is taken. The lock of the receive flow
//! controller is taken under a receiving part's lock or under none, and
//! takes none. Publishing, resizing and withdrawing an intent take only the
//! send strategy's locks for it, which take none of these. So a frame of
//! one stream waits neither for a write on another stream nor for a read.
//!
//! The application's side keeps the same order ([`application`]): a write
//! or a read takes the part's lock, and a read the receive flow
//! controller's under it; a write held back by the connection's credit lets
//! the part's lock go before it takes the set's lock, to have DATA_BLOCKED
//! sent, and registers its waker with the send flow controller, whose lock
//! takes none. Opening a stream makes its parts under the set's lock
//! without taking theirs, as a frame that creates a stream does; accepting
//! takes the set's lock only. Whoever waits keeps its waker under the lock
//! of what it waits on: to open or accept, the set's; to write or read, the
//! part's.
//!
//! Whoever changes a part, or the state under the set's lock or the
//! receive flow controller's, brings the intents of what it holds to what
//! is due now before it lets the lock go (`sync_intents`): an intent is
//! published when something is due and none is there, resized when the
//! room it needs changed, published again when its parameters changed, and
//! withdrawn when nothing is due any more. The frames of the streams, the
//! acknowledgments and losses of their packets, the peer's frames and the
//! application's operations all go through it. A stream's data and FIN have
//! one intent for its one destination; the other frames, one each.
//!
//! When the driver panicked, the layer's end is only marked in what the
//! set shares with its handles ([`StreamSet::driver_panicked`]): the wakers
//! kept under the set's lock and each part's lock are woken, and every
//! operation of the application looks at the mark first, under the lock it
//! keeps its waker under, and reports the end without changing anything.
//! The streams' state machines and the intents' tickets stay as the panic
//! left them.
//!
//! The streams of a type the peer opens below one a frame names are opened
//! with it (RFC 9000 §3.2), but only the stream the frame names gets its
//! parts; each of the others gets them when its own first frame arrives,
//! and then enters the queue of streams to accept. A late frame of a stream
//! whose state was reclaimed is ignored.
//!
//! A stream is reclaimed once each part it has is done: its sending part is
//! in "Data Recvd" or "Reset Recvd", and its receiving part owes the
//! protocol nothing more and its reader read the end or the reset, or was
//! dropped
//! ([`StreamReceiver::is_terminal`](sakuya_stream::receive::StreamReceiver::is_terminal));
//! a unidirectional stream has
//! one part only. Whoever changes a part — the driver's side with a frame,
//! a supply, an acknowledgment or a loss, the application's with an
//! operation or by dropping its handle — records under the part's lock
//! whether it is done, in a mark beside the lock that only turns from false
//! to true; with the part's lock let go, it takes the set's lock and, if
//! the marks of every part of the stream are set, takes the parts out of
//! the tables and records the reclaim with the ledger, which makes a
//! MAX_STREAMS due for a stream of the peer (RFC 9000 §4.6). The set's
//! lock only reads the marks, so it still takes no part's lock. The
//! handles of a reclaimed stream keep their parts, which hold only their
//! last result. Nothing is reclaimed once the layer ended or the driver
//! panicked.
//!
//! A part held through the shared connection, by a capability that finds
//! it by the stream's ID whenever it acts, is reclaimed as any other once
//! it is done, but its last result stays for its holder: a second mark
//! beside its lock says it is held, set when the part is handed out, under
//! the set's lock, and cleared once the capability's credential comes back
//! ([`StreamSet::reclaim_writer`], [`StreamSet::reclaim_reader`]). A part
//! reclaimed while it is held leaves its table for a table of the held
//! parts, where such a capability finds it until its credential comes
//! back.
//!
//! The events of the streams keep the same order. A part's state is read
//! under its own lock before and after each change, and its change given
//! there; a part made is given under the set's lock, before anyone else
//! has it. A reclaim that records events takes the parts out of the tables
//! under the set's lock and gives each one's last state once that lock is
//! let go, under the part's lock; one that records none lets them go under
//! the set's lock, as before.

use core::{
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
};
use std::{
    fmt,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::{Buf, BufMut, Bytes};
use sakuya_stream::{
    connection::{LayerEnd, LayerEndedError},
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::{
        AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
        ConnectionSendFlowController,
    },
    receive::stop::StopError,
    send::{
        finish::{CloseError, ResetError},
        write::{FlushError, WriteError, WriteReport},
    },
    send_buffer::{StreamSendBuffer, offset_map::OffsetMapStreamSendBuffer},
    send_options::{
        destination::{AnyActiveLinkPath, Unfulfilled},
        urgency::{SendUrgency, Urgency},
    },
    stream_id_ledger::{IdentifiedStream, ReceivingPartFrameType, SendingPartFrameType},
};
use sakuya_wire::v1::{
    application_error::ApplicationErrorCode,
    encryption_level::EncryptionLevel,
    frame::{
        data_blocked::DataBlockedFrame, max_data::MaxDataFrame,
        max_stream_data::MaxStreamDataFrame, max_streams::MaxStreamsFrame,
        reset_stream::ResetStreamFrame, stop_sending::StopSendingFrame, stream::StreamFrame,
        stream_data_blocked::StreamDataBlockedFrame, streams_blocked::StreamsBlockedFrame,
    },
    stream_id::{Directionality, StreamId},
};
use snafu::ResultExt;

use super::set_state::{
    self, ChunkOf, ConnectionReceive, DIRECTIONALITIES, MarkerOf, PartDone, PartState, ReadErrorOf,
    ReceiveTerminationReasonOf, ReceivingEnd, SendingEnd, SetState, WriteLimitReasonOf,
    forget_ticket, new_receiving_end, new_sending_end, recorded, wake_part_waiters,
};
use super::{
    FlowControlParameters, HeldReceive, HeldSend, ReceivingPartFrameSnafu, ResetStreamSnafu,
    SendingPartFrameSnafu, StreamSet, StreamSetFacts, StreamSetFrameErrorOf, StreamSnafu,
    held_part_gone,
    resets::StreamResets,
    send::{
        DataBlockedSummary, MaxDataSummary, MaxStreamDataSummary, MaxStreamsSummary,
        ResetStreamSummary, StopSendingSummary, StreamDataBlockedSummary, StreamIntent,
        StreamIntentKey, StreamSetFrameSummary, StreamSummary, StreamsBlockedSummary,
    },
};
use crate::{
    feedback::InjectSummary,
    send_strategy::{
        IntentPublisher, IntentTicketWithdraw, PublishOutcome, SharedPublishTo, SharedSendStrategy,
    },
    v1::{
        application_handles::{
            connection::wake_all, credential::HandleCredential,
            established_layer::TryOpenStreamError, stream::AllAcknowledgedError,
        },
        events::{EventInitiator, NoEvents, SharedEvents},
        send_planning::{
            ComponentIntake, ComponentPublishing, HostSendStrategyTypes, IntakeOf, IntakeTicketOf,
            PlacedIntakeHandle, StrategyPublisherOf,
        },
    },
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

pub mod application;
use application::OpenRefused;
#[cfg(feature = "reset_stream_at")]
mod reset_stream_at;
#[cfg(test)]
pub(super) mod tests;

/// The sending part of a stream as the set's table and its users share it.
type SendingPart<Lc, K, Rs, P> = Arc<LockedStreamEnd<SendingEnd<Lc, K, Rs, P>>>;

/// The receiving part of a stream as the set's table and its users share
/// it.
type ReceivingPart<Lc, K, Rs, P> = Arc<LockedStreamEnd<ReceivingEnd<Lc, K, Rs, P>>>;

/// What `mutex` holds, whether or not a holder panicked: a holder panics
/// only on a broken invariant of its own, and the state is taken as it was
/// left.
fn lock<X>(mutex: &Mutex<X>) -> MutexGuard<'_, X> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The locked stream set: the streams under one lock, each part of a
/// stream under a lock of its own; see the [module documentation](self).
///
/// `Lc` is the type of this endpoint's reason for closing, `K` the ticket
/// of a stream intent, `H` the handle of the send strategy's intake it
/// publishes its intents through, which gives `K`, `Rs` how its streams are reset
/// ([`StreamResets`]), and `P` the parameters application data is sent
/// with, by default an [`Urgency`]; all data goes to [`AnyActiveLinkPath`].
/// Of the peer's resets it takes RESET_STREAM, and RESET_STREAM_AT where
/// its streams reset reliably (`reset_stream_at::ResetStreamAtSet`, with
/// the feature `reset_stream_at`).
///
/// `E` is the handle the events of its streams are given through, by
/// default [`NoEvents`]: a part's state when it is made, each change of
/// its state, and its last state when it is reclaimed, and the data the
/// application writes and reads (see [`SharedEvents`]). Each is given under
/// the lock of the part it is of, or, for a reclaim, under the part's lock
/// once the set's lock is let go.
pub struct LockedStreamSet<Lc, K, H, Rs: StreamResets, P = Urgency, E = NoEvents> {
    shared: Arc<StreamSetShare<Lc, K, H, Rs, P, E>>,
    /// A clone of the handle in `shared`, for the driver's side to publish
    /// through without cloning it each time.
    intake: H,
}

/// The kind of [`LockedStreamSet`] whose data is sent with the parameters
/// `P`, by default an [`Urgency`].
pub struct LockedStreamSetFamily<P = Urgency>(core::marker::PhantomData<fn() -> P>);

impl<P> fmt::Debug for LockedStreamSetFamily<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LockedStreamSetFamily")
    }
}

impl<P> super::StreamSetFamily for LockedStreamSetFamily<P>
where
    P: Clone + PartialEq + Default + SendUrgency + 'static,
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>:
        StreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
{
    type Config = LockedStreamSetConfig;
    type SendParameters = P;
    type Set<
        Lc,
        I: ComponentPublishing<Self, StreamIntent<P>>,
        X: StreamResets,
        E: SharedEvents + Clone + 'static,
    > = LockedStreamSet<
        Lc,
        <I as ComponentPublishing<Self, StreamIntent<P>>>::Ticket,
        <I as ComponentPublishing<Self, StreamIntent<P>>>::Intake,
        X,
        P,
        E,
    >;
}

/// The set's capabilities can be held apart from the connection, on the
/// application's threads: it publishes through an intake of its own, on
/// the driver's side too, and keeps the intake's tickets either way. Its
/// kind gives the strategy types whose strategy gives intakes.
impl<I, P> ComponentPublishing<LockedStreamSetFamily<P>, StreamIntent<P>> for I
where
    I: HostSendStrategyTypes,
    I::Strategy: SharedSendStrategy<I>,
    IntakeOf<I>: PublishOutcome<StreamIntent<P>, AnyActiveLinkPath>,
{
    type Ticket = IntakeTicketOf<I, StreamIntent<P>>;
    type Intake = PlacedIntakeHandle<IntakeOf<I>, StreamIntent<P>, AnyActiveLinkPath, Self::Ticket>;
}

/// The intake is the core's, with the place of the stream intents fixed.
impl<I, P, Idx> ComponentIntake<LockedStreamSetFamily<P>, StreamIntent<P>, Idx> for I
where
    I: HostSendStrategyTypes,
    I::Strategy: SharedSendStrategy<I>,
    IntakeOf<I>: SharedPublishTo<StreamIntent<P>, AnyActiveLinkPath, Idx>,
{
    fn intake(strategy: &mut I::Strategy) -> Self::Intake {
        PlacedIntakeHandle::new::<Idx>(strategy.intake())
    }
}

/// The handle of a [`LockedStreamSet`]: it shares the set's state.
pub struct LockedStreamSetHandle<Lc, K, H, Rs: StreamResets, P = Urgency, E = NoEvents> {
    shared: Arc<StreamSetShare<Lc, K, H, Rs, P, E>>,
}

impl<Lc, K, H, Rs: StreamResets, P, E> Clone for LockedStreamSetHandle<Lc, K, H, Rs, P, E> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<Lc, K, H, Rs: StreamResets, P, E> StreamSetShare<Lc, K, H, Rs, P, E> {
    /// The driver panicked: mark the end in what the set shares with its
    /// handles and wake who waits to open, accept, write or read; the
    /// wakers are taken out of the set's lock and each part's lock, one lock
    /// at a time, and nothing else changes under them.
    fn driver_panicked(&self, end: LayerEnd<Lc>) {
        let shared = self;
        if shared.panic_end.set(end).is_err() {
            return;
        }
        let (senders, receivers) = {
            let mut set = lock(&shared.set);
            for directionality in DIRECTIONALITIES {
                wake_all(set.open_wakers.get_mut(directionality));
                wake_all(set.accept_wakers.get_mut(directionality));
            }
            (
                set.senders.values().cloned().collect::<Vec<_>>(),
                set.receivers.values().cloned().collect::<Vec<_>>(),
            )
        };
        for sender in senders {
            let writers = core::mem::take(&mut sender.lock().writer);
            wake_part_waiters(writers);
        }
        for receiver in receivers {
            let readers = core::mem::take(&mut receiver.lock().reader);
            wake_part_waiters(readers);
        }
    }
}

impl<Lc, K, H, Rs: StreamResets, P, E> StreamSetShare<Lc, K, H, Rs, P, E> {
    /// How the layer ended, if the driver panicked.
    fn panic_end(&self) -> Option<&LayerEnd<Lc>> {
        self.panic_end.get()
    }

    /// What the peer allows the resets of the set, under the set's lock,
    /// which is let go before it is used: what its parameters of this
    /// handshake allow once they are known, before that what the set was
    /// made on allows.
    #[cfg(feature = "reset_stream_at")]
    fn peer_reset_support(&self) -> Rs::PeerSupport {
        lock(&self.set).peer_reset_support
    }
}

impl<Lc, K, H, Rs: StreamResets, P, E> fmt::Debug for LockedStreamSetHandle<Lc, K, H, Rs, P, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedStreamSetHandle")
            .finish_non_exhaustive()
    }
}

impl<Lc, K, H, Rs: StreamResets, P, E> fmt::Debug for LockedStreamSet<Lc, K, H, Rs, P, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedStreamSet").finish_non_exhaustive()
    }
}

/// What [`LockedStreamSet`] is configured with: the error codes of the
/// resets and STOP_SENDING frames the default policies of its streams send
/// by themselves. Each is 0 by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockedStreamSetConfig {
    /// The code a stream resets with when the application gives up its
    /// stream writer.
    pub send_abandon_code: ApplicationErrorCode,
    /// The code a stream resets with when data has no destination left to
    /// fall back to.
    pub destination_exhausted_code: ApplicationErrorCode,
    /// The code a stream asks the peer to stop sending with when the
    /// application drops its stream reader.
    pub receive_abandon_code: ApplicationErrorCode,
}

/// One part of one stream, under a lock of its own; `X` is the sending or
/// the receiving part, with the tickets of the intents of its frames.
///
/// Beside the lock it keeps whether the part was found done — its protocol
/// duties over and the application's last result taken or given up — which
/// only turns from false to true: whoever changes the part records it under
/// the part's lock, and the set reads it under the set's lock without
/// taking the part's. It also keeps whether the part is held through the
/// shared connection: such a part, once reclaimed, is kept for its holder
/// until the holder's credential comes back.
pub struct LockedStreamEnd<X> {
    end: Mutex<X>,
    done: AtomicBool,
    held: AtomicBool,
}

impl<X> LockedStreamEnd<X> {
    fn new(end: X) -> Self {
        Self {
            end: Mutex::new(end),
            done: AtomicBool::new(false),
            held: AtomicBool::new(false),
        }
    }

    /// The part is held through the shared connection from now on: set
    /// under the set's lock, before the part is handed out.
    fn hold(&self) {
        self.held.store(true, Ordering::Release);
    }

    /// The holder's credential came back: the part is not kept for it once
    /// reclaimed.
    fn let_go(&self) {
        self.held.store(false, Ordering::Release);
    }

    /// Whether the part is held through the shared connection.
    fn is_held(&self) -> bool {
        self.held.load(Ordering::Acquire)
    }

    /// The part, for one operation. Taken under no lock of the set; the
    /// lock of the connection's receive flow controller may be taken under
    /// it.
    pub fn lock(&self) -> MutexGuard<'_, X> {
        lock(&self.end)
    }

    /// Whether the part was found done; read without the part's lock.
    fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Record whether the part is done, `end` being what its lock holds:
    /// called under that lock after a change, before the lock is let go.
    fn note_done(&self, end: &X)
    where
        X: PartDone,
    {
        if end.is_done() {
            self.done.store(true, Ordering::Release);
        }
    }
}

impl<X> fmt::Debug for LockedStreamEnd<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedStreamEnd").finish_non_exhaustive()
    }
}

// ---- the set ----

/// What the set and its handles share, with the handle `H` of the
/// strategy's intake everything of the set publishes through.
struct StreamSetShare<Lc, K, H, Rs: StreamResets, P, E> {
    /// How the layer ended, once the driver panicked: only marked, with
    /// the state under the locks left as the panic left it. Every operation
    /// of the application looks at it first, under the lock its waker is
    /// kept under.
    panic_end: OnceLock<LayerEnd<Lc>>,
    set: Mutex<SetStateOf<Lc, K, Rs, P>>,
    connection_receive: Mutex<ConnectionReceive<K, P>>,
    connection_send: Arc<AtomicConnectionSendFlowController>,
    facts: StreamSetFacts<Rs::PeerSupport>,
    config: LockedStreamSetConfig,
    /// The handle the events of the streams are given through.
    events: E,
    /// The handle of the strategy's intake the set's intents are published
    /// through, from the driver's side and the application's alike; cloned
    /// by whoever publishes.
    intake: H,
}

/// What the set's lock holds.
type SetStateOf<Lc, K, Rs, P> = SetState<
    Lc,
    K,
    P,
    SendingPart<Lc, K, Rs, P>,
    ReceivingPart<Lc, K, Rs, P>,
    <Rs as StreamResets>::PeerSupport,
>;

impl<Lc, K, Rs: StreamResets, P> SetStateOf<Lc, K, Rs, P> {
    /// Reclaim the stream `id` if each part it has is done: its parts
    /// leave the tables and the ledger records the reclaim, which lets the
    /// peer open one more stream of the type when the stream is the peer's;
    /// a part held through the shared connection goes into the table of the
    /// held parts. Whether a part is done is read from the mark beside its lock
    /// ([`LockedStreamEnd::is_done`]), without taking the lock. Nothing is
    /// reclaimed once the layer ended, nor a stream reclaimed already.
    /// The parts taken out of the tables, if it was reclaimed now.
    fn reclaim_if_done(&mut self, id: StreamId) -> Option<ReclaimedParts<Lc, K, Rs, P>> {
        if self.end.is_some() {
            return None;
        }
        let sending = self.senders.get(&id);
        let receiving = self.receivers.get(&id);
        // invariant: a stream gets every part it has when it is created, and
        // the parts leave the tables together
        debug_assert!(
            id.directionality() == Directionality::Unidirectional
                || sending.is_some() == receiving.is_some(),
            "a bidirectional stream {id} has one part in the tables"
        );
        if sending.is_none() && receiving.is_none() {
            // reclaimed already, by whoever saw both parts done first
            return None;
        }
        if !sending.is_none_or(|part| part.is_done())
            || !receiving.is_none_or(|part| part.is_done())
        {
            return None;
        }
        let parts = (self.senders.remove(&id), self.receivers.remove(&id));
        if let Some(part) = parts.0.as_ref().filter(|part| part.is_held()) {
            self.held_senders.insert(id, Arc::clone(part));
        }
        if let Some(part) = parts.1.as_ref().filter(|part| part.is_held()) {
            self.held_receivers.insert(id, Arc::clone(part));
        }
        let reclaimed = self.ledger.reclaim(id);
        // invariant: a stream in the tables was opened and created, and is
        // reclaimed only here, when it leaves them
        debug_assert!(
            reclaimed.is_ok(),
            "stream {id} is reclaimed once: {reclaimed:?}"
        );
        Some(parts)
    }
}

/// The parts of a stream as reclaiming takes them out of the tables: the
/// sending part, unless the peer opened it unidirectional; the receiving
/// part, unless this side opened it unidirectional.
type ReclaimedParts<Lc, K, Rs, P> = (
    Option<SendingPart<Lc, K, Rs, P>>,
    Option<ReceivingPart<Lc, K, Rs, P>>,
);

impl<Lc, K, H, Rs: StreamResets, P, E> StreamSetShare<Lc, K, H, Rs, P, E>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    E: SharedEvents,
{
    /// Make the parts of `id`, a stream the peer opened that a frame just
    /// created, and queue it to be accepted. A bidirectional stream gets
    /// both parts, a unidirectional one its receiving part. Each part made
    /// is an event of the peer's.
    fn create_peer_stream(&self, set: &mut SetStateOf<Lc, K, Rs, P>, id: StreamId) {
        let receiving = new_receiving_end(&self.facts, id, self.config.receive_abandon_code);
        self.part_made(id, &receiving, EventInitiator::Remote);
        set.receivers
            .insert(id, Arc::new(LockedStreamEnd::new(receiving)));
        match id.directionality() {
            Directionality::Bidirectional => {
                let sending = new_sending_end(
                    &self.facts,
                    &set.granted_by_peer,
                    id,
                    self.config.send_abandon_code,
                    self.config.destination_exhausted_code,
                    &self.connection_send,
                );
                self.part_made(id, &sending, EventInitiator::Remote);
                set.senders
                    .insert(id, Arc::new(LockedStreamEnd::new(sending)));
                set.accept_bidirectional.push_back(id);
            }
            Directionality::Unidirectional => set.accept_unidirectional.push_back(id),
        }
        wake_all(set.accept_wakers.get_mut(id.directionality()));
    }

    /// The receiving part of `id` for a frame of `frame_type`, once the
    /// frame passed the checks of the streams' identity: made if the frame
    /// creates the stream; `None` when the frame is to be ignored, as the
    /// stream was reclaimed or the layer ended.
    #[allow(clippy::type_complexity)] // a part of four type parameters
    fn receiving_part(
        &self,
        id: StreamId,
        frame_type: ReceivingPartFrameType,
    ) -> Result<Option<ReceivingPart<Lc, K, Rs, P>>, StreamSetFrameErrorOf<Rs>> {
        let mut set = lock(&self.set);
        if set.end.is_some() {
            return Ok(None);
        }
        match set
            .ledger
            .on_receiving_part_frame(id, frame_type)
            .context(ReceivingPartFrameSnafu)?
        {
            IdentifiedStream::Created => self.create_peer_stream(&mut set, id),
            IdentifiedStream::Existing => {}
            IdentifiedStream::Reclaimed => return Ok(None),
        }
        let part = set.receivers.get(&id).cloned();
        // invariant: a stream gets its parts when it is created, and leaves
        // the tables only when it is reclaimed
        debug_assert!(part.is_some(), "stream {id} has no receiving part");
        Ok(part)
    }

    /// The sending part of `id` for a frame of `frame_type`, as
    /// [`receiving_part`](Self::receiving_part) finds the receiving part.
    #[allow(clippy::type_complexity)] // a part of four type parameters
    fn sending_part(
        &self,
        id: StreamId,
        frame_type: SendingPartFrameType,
    ) -> Result<Option<SendingPart<Lc, K, Rs, P>>, StreamSetFrameErrorOf<Rs>> {
        let mut set = lock(&self.set);
        if set.end.is_some() {
            return Ok(None);
        }
        match set
            .ledger
            .on_sending_part_frame(id, frame_type)
            .context(SendingPartFrameSnafu)?
        {
            // a bidirectional stream of the peer, opened by a frame for its
            // sending part (RFC 9000 §3.2, §19.5, §19.10)
            IdentifiedStream::Created => self.create_peer_stream(&mut set, id),
            IdentifiedStream::Existing => {}
            IdentifiedStream::Reclaimed => return Ok(None),
        }
        let part = set.senders.get(&id).cloned();
        // invariant: as for the receiving part
        debug_assert!(part.is_some(), "stream {id} has no sending part");
        Ok(part)
    }

    /// The sending part of `id` that a frame source writes or takes back
    /// the frames of: `None` once it left the table.
    fn sender_of(&self, id: StreamId) -> Option<SendingPart<Lc, K, Rs, P>> {
        lock(&self.set).senders.get(&id).cloned()
    }

    /// The receiving part of `id`, as [`sender_of`](Self::sender_of).
    fn receiver_of(&self, id: StreamId) -> Option<ReceivingPart<Lc, K, Rs, P>> {
        lock(&self.set).receivers.get(&id).cloned()
    }

    /// The sending part of `id` for its holder through the shared
    /// connection: in its table, or in the table of the held parts once it
    /// was reclaimed; with `forget`, it leaves the latter.
    pub(super) fn held_sender_of(
        &self,
        id: StreamId,
        forget: bool,
    ) -> Option<SendingPart<Lc, K, Rs, P>> {
        let mut set = lock(&self.set);
        if let Some(part) = set.senders.get(&id) {
            return Some(Arc::clone(part));
        }
        if forget {
            set.held_senders.remove(&id)
        } else {
            set.held_senders.get(&id).cloned()
        }
    }

    /// The receiving part of `id` for its holder, as
    /// [`held_sender_of`](Self::held_sender_of).
    pub(super) fn held_receiver_of(
        &self,
        id: StreamId,
        forget: bool,
    ) -> Option<ReceivingPart<Lc, K, Rs, P>> {
        let mut set = lock(&self.set);
        if let Some(part) = set.receivers.get(&id) {
            return Some(Arc::clone(part));
        }
        if forget {
            set.held_receivers.remove(&id)
        } else {
            set.held_receivers.get(&id).cloned()
        }
    }

    /// The sending part of `id` for an operation of its holder through the
    /// shared connection ([`held_sender_of`](Self::held_sender_of)), while
    /// it is held: `None` once the holder's credential came back.
    fn held_sending(&self, id: StreamId) -> Option<SendingPart<Lc, K, Rs, P>> {
        self.held_sender_of(id, false).filter(|part| part.is_held())
    }

    /// The receiving part of `id` for an operation of its holder, as
    /// [`held_sending`](Self::held_sending).
    fn held_receiving(&self, id: StreamId) -> Option<ReceivingPart<Lc, K, Rs, P>> {
        self.held_receiver_of(id, false)
            .filter(|part| part.is_held())
    }

    /// Change the sending part of `id` with `change`, on the action of
    /// `trigger`, as [`change_sender`](Self::change_sender) does; nothing
    /// once the part left the table.
    fn with_sender(
        &self,
        id: StreamId,
        publish: &mut H,
        trigger: EventInitiator,
        change: impl FnOnce(&mut SendingEnd<Lc, K, Rs, P>, &mut H),
    ) {
        if let Some(part) = self.sender_of(id) {
            self.change_sender(&part, id, publish, trigger, change);
        }
    }

    /// Change the receiving part of `id`, as
    /// [`with_sender`](Self::with_sender).
    fn with_receiver(
        &self,
        id: StreamId,
        publish: &mut H,
        trigger: EventInitiator,
        change: impl FnOnce(&mut ReceivingEnd<Lc, K, Rs, P>, &mut H),
    ) {
        if let Some(part) = self.receiver_of(id) {
            self.change_receiver(&part, id, publish, trigger, change);
        }
    }

    /// Change `part`, the sending part of `id`, with `change`, under its own
    /// lock, bring its intents to what is due then, and give the change of
    /// its state, on the action of `trigger`; with the lock let go, reclaim
    /// the stream if it is done ([`reclaim_if_done`](Self::reclaim_if_done)).
    /// `change` is given `publish` too, for a frame written to let its
    /// ticket go.
    fn change_sender<R>(
        &self,
        part: &SendingPart<Lc, K, Rs, P>,
        id: StreamId,
        publish: &mut H,
        trigger: EventInitiator,
        change: impl FnOnce(&mut SendingEnd<Lc, K, Rs, P>, &mut H) -> R,
    ) -> R {
        let result = {
            let mut end = part.lock();
            let before = self.state_before(&*end);
            let result = change(&mut end, publish);
            end.sync_intents(publish);
            part.note_done(&end);
            self.state_after(id, before, &*end, trigger);
            result
        };
        self.reclaim_if_done(part, id, publish);
        result
    }

    /// Change `part`, the receiving part of `id`, as
    /// [`change_sender`](Self::change_sender) the sending part.
    fn change_receiver<R>(
        &self,
        part: &ReceivingPart<Lc, K, Rs, P>,
        id: StreamId,
        publish: &mut H,
        trigger: EventInitiator,
        change: impl FnOnce(&mut ReceivingEnd<Lc, K, Rs, P>, &mut H) -> R,
    ) -> R {
        let result = {
            let mut end = part.lock();
            let before = self.state_before(&*end);
            let result = change(&mut end, publish);
            end.sync_intents(id, publish);
            part.note_done(&end);
            self.state_after(id, before, &*end, trigger);
            result
        };
        self.reclaim_if_done(part, id, publish);
        result
    }

    /// Reclaim the stream `id` if each part it has is done, `changed` being
    /// the part of it just changed; under the set's lock, taken here, and
    /// with the MAX_STREAMS it makes due published.
    ///
    /// Called by whoever changed a part of the stream, the driver's side or
    /// the application's, once it let the part's lock go and recorded
    /// whether the part is done ([`LockedStreamEnd::note_done`]): the set's
    /// lock is not taken while `changed` is not done, as the stream cannot
    /// be reclaimed then. When both parts of a stream become done, by two
    /// changes that may run at once, whichever of the two takes the set's
    /// lock later finds both done: each part's mark is set before its
    /// changer takes the set's lock, and the set's lock orders the two.
    /// Once the driver panicked, nothing is reclaimed.
    ///
    /// When the events are recorded, the parts taken out of the tables come
    /// back here, and each gives its last state once the set's lock is let
    /// go, under its own lock; otherwise they are let go under the set's
    /// lock.
    fn reclaim_if_done<X>(&self, changed: &LockedStreamEnd<X>, id: StreamId, publish: &mut H) {
        if !changed.is_done() || self.panic_end().is_some() {
            return;
        }
        if self.events().is_some() {
            let reclaimed = self.with_set(publish, |set, _| set.reclaim_if_done(id));
            if let Some((sending, receiving)) = reclaimed {
                if let Some(part) = sending {
                    self.part_reclaimed(id, &part);
                }
                if let Some(part) = receiving {
                    self.part_reclaimed(id, &part);
                }
            }
        } else {
            self.with_set(publish, |set, _| {
                set.reclaim_if_done(id);
            });
        }
    }

    // ---- the events of the streams ----

    /// The handle for the events of the streams, when they are recorded.
    #[inline(always)]
    fn events(&self) -> Option<&E> {
        recorded(&self.events)
    }

    /// The part `end` of `id` was just made, on the action of `trigger`:
    /// it leaves idle for the state it starts in.
    fn part_made<X: PartState>(&self, id: StreamId, end: &X, trigger: EventInitiator) {
        set_state::part_made(&self.events, id, end, trigger);
    }

    /// The state of `end` before a change, read only when the events are
    /// recorded; called under the part's lock.
    #[inline(always)]
    fn state_before<X: PartState>(&self, end: &X) -> Option<X::State> {
        set_state::state_before(&self.events, end)
    }

    /// After a change of the part `end` of `id`, on the action of
    /// `trigger`, still under its lock: its state change, if its state
    /// differs from `before`, what [`state_before`](Self::state_before)
    /// read.
    #[inline(always)]
    fn state_after<X: PartState>(
        &self,
        id: StreamId,
        before: Option<X::State>,
        end: &X,
        trigger: EventInitiator,
    ) {
        set_state::state_after(&self.events, id, before, end, trigger);
    }

    /// The part `part` of `id` was reclaimed: its last state, read under its
    /// lock, which is taken here, under no lock of the set.
    fn part_reclaimed<X: PartState>(&self, id: StreamId, part: &LockedStreamEnd<X>) {
        if self.events().is_some() {
            set_state::part_reclaimed(&self.events, id, &*part.lock());
        }
    }

    /// Change what the set's lock holds with `change`, which is given
    /// `publish` too, and bring the connection's intents there to what is
    /// due then.
    fn with_set<R>(
        &self,
        publish: &mut H,
        change: impl FnOnce(&mut SetStateOf<Lc, K, Rs, P>, &mut H) -> R,
    ) -> R {
        let mut set = lock(&self.set);
        let result = change(&mut set, publish);
        set.sync_intents(publish);
        result
    }

    /// Change what the receive flow controller's lock holds with `change`,
    /// which is given `publish` too, and bring the MAX_DATA intent to what
    /// is due then.
    fn with_connection_receive<R>(
        &self,
        publish: &mut H,
        change: impl FnOnce(&mut ConnectionReceive<K, P>, &mut H) -> R,
    ) -> R {
        let mut connection = lock(&self.connection_receive);
        let result = change(&mut connection, publish);
        connection.sync_intents(publish);
        result
    }
}

/// `P` is a send parameter the default send buffer orders data by. The
/// peer's frames and the acknowledgments of what this side sent are the
/// peer's actions on a part; what this side writes, the losses it declares
/// and the ends of the strategy's intents are this side's.
///
/// Everything it publishes goes through its intake, `H`; the strategy's
/// publisher it is lent stays as it is.
impl<Lc, K, H, I, Rs: StreamResets, P, E> StreamSet<Lc, I, Rs>
    for LockedStreamSet<Lc, K, H, Rs, P, E>
where
    I: HostSendStrategyTypes,
    K: IntentTicketWithdraw,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    P: Clone + PartialEq + Default + SendUrgency,
    E: SharedEvents,
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>:
        StreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
{
    type Handle = LockedStreamSetHandle<Lc, K, H, Rs, P, E>;
    type Config = LockedStreamSetConfig;
    type SendParameters = P;
    type Events = E;
    type Intake = H;
    type WriteLimitReason = WriteLimitReasonOf<Rs, P>;
    type ReceiveTerminationReason = ReceiveTerminationReasonOf<Rs>;
    type Chunk = ChunkOf;

    fn new(
        facts: StreamSetFacts<Rs::PeerSupport>,
        config: LockedStreamSetConfig,
        events: E,
        intake: H,
    ) -> Self {
        let set = SetState::new(&facts);
        Self {
            shared: Arc::new(StreamSetShare {
                panic_end: OnceLock::new(),
                set: Mutex::new(set),
                connection_receive: Mutex::new(ConnectionReceive {
                    flow: ConnectionReceiveFlowController::new(
                        facts.granted_to_peer.initial_max_data.get(),
                    ),
                    max_data: None,
                    max_data_lost: false,
                    ended: false,
                }),
                connection_send: Arc::new(AtomicConnectionSendFlowController::new(
                    facts.granted_by_peer.initial_max_data.get(),
                )),
                facts,
                config,
                events,
                intake: intake.clone(),
            }),
            intake,
        }
    }

    fn handle(&self) -> LockedStreamSetHandle<Lc, K, H, Rs, P, E> {
        LockedStreamSetHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A STREAM frame in a 0-RTT packet marks its stream
    /// ([`StreamReceiver::received_zero_rtt`](sakuya_stream::receive::StreamReceiver::received_zero_rtt))
    /// once the stream took it.
    fn on_stream_frame<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        level: EncryptionLevel,
        frame: StreamFrame<Bytes>,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>> {
        let publish = &mut self.intake;
        let id = frame.stream_id().get();
        let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::Stream)?
        else {
            return Ok(());
        };
        let mut end = part.lock();
        let before = self.shared.state_before(&*end);
        {
            let mut connection = lock(&self.shared.connection_receive);
            end.receiver
                .on_stream_frame(frame, &mut connection.flow)
                .context(StreamSnafu)?;
        }
        if level == EncryptionLevel::ZeroRtt {
            end.receiver.mark_received_zero_rtt();
        }
        end.sync_intents(id, publish);
        end.wake_reader();
        part.note_done(&end);
        self.shared
            .state_after(id, before, &*end, EventInitiator::Remote);
        drop(end);
        self.shared.reclaim_if_done(&part, id, publish);
        Ok(())
    }

    fn on_reset_stream<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        frame: ResetStreamFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>> {
        let publish = &mut self.intake;
        let id = frame.stream_id().get();
        let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::ResetStream)?
        else {
            return Ok(());
        };
        let mut end = part.lock();
        let before = self.shared.state_before(&*end);
        {
            let mut connection = lock(&self.shared.connection_receive);
            Rs::on_reset_stream(&mut end.receiver, frame, &mut connection.flow)
                .context(ResetStreamSnafu)?;
        }
        end.sync_intents(id, publish);
        end.wake_reader();
        part.note_done(&end);
        self.shared
            .state_after(id, before, &*end, EventInitiator::Remote);
        drop(end);
        self.shared.reclaim_if_done(&part, id, publish);
        Ok(())
    }

    fn on_stop_sending<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        frame: StopSendingFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>> {
        let publish = &mut self.intake;
        let id = frame.stream_id().get();
        if let Some(part) = self
            .shared
            .sending_part(id, SendingPartFrameType::StopSending)?
        {
            let mut end = part.lock();
            let before = self.shared.state_before(&*end);
            end.sender
                .on_stop_sending(frame.application_error_code().get());
            end.sync_intents(publish);
            end.wake_writer();
            part.note_done(&end);
            self.shared
                .state_after(id, before, &*end, EventInitiator::Remote);
            drop(end);
            self.shared.reclaim_if_done(&part, id, publish);
        }
        Ok(())
    }

    /// A larger limit clears the DATA_BLOCKED signal of a lower one.
    fn on_max_data<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        frame: MaxDataFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>> {
        let publish = &mut self.intake;
        self.shared
            .connection_send
            .on_max_data(frame.maximum_data().get());
        let limit = self.shared.connection_send.limit();
        self.shared.with_set(publish, |set, _| {
            set.connection.data_blocked_signal.on_limit_raised(limit);
        });
        Ok(())
    }

    fn on_max_stream_data<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        frame: MaxStreamDataFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>> {
        let publish = &mut self.intake;
        let id = frame.stream_id().get();
        if let Some(part) = self
            .shared
            .sending_part(id, SendingPartFrameType::MaxStreamData)?
        {
            let mut end = part.lock();
            let before = self.shared.state_before(&*end);
            end.sender
                .on_max_stream_data(frame.maximum_stream_data().get());
            end.sync_intents(publish);
            end.wake_writer();
            part.note_done(&end);
            self.shared
                .state_after(id, before, &*end, EventInitiator::Remote);
            drop(end);
            self.shared.reclaim_if_done(&part, id, publish);
        }
        Ok(())
    }

    /// A limit that does not grow is ignored (RFC 9000 §19.11).
    fn on_max_streams<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        frame: MaxStreamsFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>> {
        let publish = &mut self.intake;
        self.shared
            .with_set(publish, |set, _| set.on_max_streams(&frame));
        Ok(())
    }

    /// The default policies send nothing for it; it changes nothing.
    fn on_data_blocked<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        _: DataBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>> {
        Ok(())
    }

    fn on_stream_data_blocked<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        frame: StreamDataBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>> {
        let publish = &mut self.intake;
        let id = frame.stream_id().get();
        if let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::StreamDataBlocked)?
        {
            self.shared
                .change_receiver(&part, id, publish, EventInitiator::Remote, |end, _| {
                    end.receiver
                        .on_stream_data_blocked(frame.maximum_stream_data().get());
                });
        }
        Ok(())
    }

    /// The default policies send nothing for it; it changes nothing. A
    /// limit beyond 2^60 is refused when the frame is read (RFC 9000
    /// §19.14).
    fn on_streams_blocked<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        _: StreamsBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>> {
        Ok(())
    }

    /// The end is kept first, under the set's lock; each part hears of it
    /// afterwards, under its own lock. Only the first end is kept. Every
    /// ticket is dropped, which withdraws its intent: nothing of the layer
    /// is sent any more.
    /// The end is marked in what the set shares with its handles, and who
    /// waits is woken; nothing else changes.
    fn driver_panicked(&mut self, end: LayerEnd<Lc>) {
        self.shared.driver_panicked(end);
    }

    fn open_held<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        directionality: Directionality,
        waker: Option<&Waker>,
    ) -> Result<StreamId, TryOpenStreamError<Lc>> {
        let publish = &mut self.intake;
        match self.shared.open_local(directionality, publish, waker, true) {
            Ok((id, _)) => Ok(id),
            Err(OpenRefused::AtLimit) => Err(TryOpenStreamError::AtLimit),
            Err(OpenRefused::Ended(end)) => Err(LayerEndedError::new(end).into()),
        }
    }

    fn poll_accept_held(
        &mut self,
        cx: &mut Context<'_>,
        directionality: Directionality,
    ) -> Poll<Result<StreamId, LayerEndedError<Lc>>> {
        self.shared
            .poll_accept(cx, directionality, true)
            .map(|accepted| match accepted {
                Ok((id, _)) => Ok(id),
                Err(end) => Err(LayerEndedError::new(end)),
            })
    }

    /// The credential has no content: it only says that the writer is let
    /// go now.
    fn reclaim_writer<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        id: StreamId,
        _credential: HandleCredential,
    ) {
        if let Some(part) = self.shared.held_sender_of(id, true) {
            self.shared.sending_access(&part).give_up();
        }
    }

    /// As [`reclaim_writer`](Self::reclaim_writer) for the reader.
    fn reclaim_reader<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        id: StreamId,
        _credential: HandleCredential,
    ) {
        if let Some(part) = self.shared.held_receiver_of(id, true) {
            self.shared.receiving_access(&part, id).give_up();
        }
    }

    /// The part is found by its ID, while it is held: in its table, or in
    /// the table of the held parts once the stream was reclaimed. It
    /// publishes through its intake.
    fn poll_write<Ij, Kp, B: Buf + ?Sized>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        held: HeldSend<'_>,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &P,
        destination: &AnyActiveLinkPath,
    ) -> Poll<Result<WriteReport, WriteError<WriteLimitReasonOf<Rs, P>, Lc>>> {
        match self.shared.held_sending(held.stream_id()) {
            Some(part) => self.shared.sending_access(&part).poll_write_with(
                cx,
                input,
                parameters,
                destination,
            ),
            None => Poll::Ready(Err(held_part_gone(held.stream_id()).into())),
        }
    }

    fn close<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        held: HeldSend<'_>,
    ) -> Result<(), CloseError<Lc>> {
        match self.shared.held_sending(held.stream_id()) {
            Some(part) => self.shared.sending_access(&part).close(),
            None => Err(held_part_gone(held.stream_id()).into()),
        }
    }

    fn reset<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        held: HeldSend<'_>,
        code: ApplicationErrorCode,
    ) -> Result<(), ResetError<Lc>> {
        match self.shared.held_sending(held.stream_id()) {
            Some(part) => self.shared.sending_access(&part).reset(code),
            None => Err(held_part_gone(held.stream_id()).into()),
        }
    }

    /// Writes go into the send buffer at once: nothing is held back, and it
    /// is ready at once.
    fn poll_flushed(
        &mut self,
        held: HeldSend<'_>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), FlushError<Lc>>> {
        Poll::Ready(match self.shared.held_sending(held.stream_id()) {
            Some(part) => self.shared.sending_access(&part).flush(),
            None => Err(held_part_gone(held.stream_id()).into()),
        })
    }

    fn poll_all_acknowledged(
        &mut self,
        held: HeldSend<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), AllAcknowledgedError<Lc>>> {
        match self.shared.held_sending(held.stream_id()) {
            Some(part) => self.shared.sending_access(&part).poll_all_acknowledged(cx),
            None => Poll::Ready(Err(held_part_gone(held.stream_id()).into())),
        }
    }

    fn poll_read_into<Ij, Kp, O: BufMut + ?Sized>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        held: HeldReceive<'_>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, ReadErrorOf<Lc, Rs>>> {
        let id = held.stream_id();
        match self.shared.held_receiving(id) {
            Some(part) => self
                .shared
                .receiving_access(&part, id)
                .poll_read_into(cx, destination),
            None => Poll::Ready(Err(held_part_gone(id).into())),
        }
    }

    fn poll_read_chunk<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        held: HeldReceive<'_>,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<ChunkOf>, ReadErrorOf<Lc, Rs>>> {
        let id = held.stream_id();
        match self.shared.held_receiving(id) {
            Some(part) => self
                .shared
                .receiving_access(&part, id)
                .poll_read_chunk(cx, maximum),
            None => Poll::Ready(Err(held_part_gone(id).into())),
        }
    }

    fn stop<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        held: HeldReceive<'_>,
        code: ApplicationErrorCode,
    ) -> Result<(), StopError<Lc>> {
        let id = held.stream_id();
        match self.shared.held_receiving(id) {
            Some(part) => self.shared.receiving_access(&part, id).stop(code),
            None => Err(held_part_gone(id).into()),
        }
    }

    fn received_zero_rtt(&self, held: HeldReceive<'_>) -> bool {
        let id = held.stream_id();
        self.shared
            .held_receiving(id)
            .is_some_and(|part| self.shared.receiving_access(&part, id).received_zero_rtt())
    }

    /// Under the set's lock, then each part's; the limits grow as
    /// MAX_DATA, MAX_STREAM_DATA and MAX_STREAMS make them.
    fn peer_transport_parameters_known<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        granted_by_peer: FlowControlParameters,
        peer_reset_support: Rs::PeerSupport,
    ) {
        let publish = &mut self.intake;
        let shared = &self.shared;
        let senders = shared.with_set(publish, |set, _| {
            if set.end.is_some() {
                return Vec::new();
            }
            set.peer_parameters_known(&granted_by_peer, peer_reset_support);
            shared
                .connection_send
                .on_max_data(granted_by_peer.initial_max_data.get());
            let limit = shared.connection_send.limit();
            set.connection.data_blocked_signal.on_limit_raised(limit);
            set.senders
                .iter()
                .map(|(id, part)| (*id, Arc::clone(part)))
                .collect()
        });
        for (id, part) in senders {
            let mut end = part.lock();
            let before = shared.state_before(&*end);
            end.sender
                .on_max_stream_data(shared.facts.send_limit(&granted_by_peer, id));
            end.sync_intents(publish);
            end.wake_writer();
            part.note_done(&end);
            shared.state_after(id, before, &*end, EventInitiator::Remote);
            drop(end);
            shared.reclaim_if_done(&part, id, publish);
        }
    }

    /// Under the set's lock, then each part's; the intents are withdrawn
    /// through the set's intake.
    fn layer_ended<Ij, Kp>(&mut self, _: &mut StrategyPublisherOf<I>, end: LayerEnd<Lc>) {
        let publish = &mut self.intake;
        let (senders, receivers) = {
            let mut set = lock(&self.shared.set);
            if !set.layer_ended(end.clone(), publish) {
                return;
            }
            (
                set.senders.values().cloned().collect::<Vec<_>>(),
                set.receivers.values().cloned().collect::<Vec<_>>(),
            )
        };
        lock(&self.shared.connection_receive).layer_ended(publish);
        for sender in senders {
            sender.lock().layer_ended(end.clone(), publish);
        }
        for receiver in receivers {
            receiver.lock().layer_ended(end.clone(), publish);
        }
    }

    fn supply_stream<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        urgency: Urgency,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut self.intake;
        let Some(part) = self.shared.sender_of(stream_id) else {
            return Supplied::Open(packet);
        };
        self.shared.change_sender(
            &part,
            stream_id,
            publish,
            EventInitiator::Local,
            |end, _| end.write_stream(urgency, packet),
        )
    }

    fn supply_reset_stream<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<ResetStreamSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut self.intake;
        let Some(part) = self.shared.sender_of(stream_id) else {
            return Supplied::Open(packet);
        };
        self.shared.change_sender(
            &part,
            stream_id,
            publish,
            EventInitiator::Local,
            |end, publish| end.write_reset_stream(publish, packet),
        )
    }

    fn supply_stop_sending<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StopSendingSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut self.intake;
        let Some(part) = self.shared.receiver_of(stream_id) else {
            return Supplied::Open(packet);
        };
        self.shared.change_receiver(
            &part,
            stream_id,
            publish,
            EventInitiator::Local,
            |end, publish| end.write_stop_sending(publish, stream_id, packet),
        )
    }

    fn supply_max_data<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxDataSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut self.intake;
        self.shared
            .with_connection_receive(publish, |connection, publish| {
                connection.write_max_data(publish, packet)
            })
    }

    fn supply_max_stream_data<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamDataSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut self.intake;
        let Some(part) = self.shared.receiver_of(stream_id) else {
            return Supplied::Open(packet);
        };
        self.shared.change_receiver(
            &part,
            stream_id,
            publish,
            EventInitiator::Local,
            |end, publish| end.write_max_stream_data(publish, stream_id, packet),
        )
    }

    fn supply_max_streams<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        directionality: Directionality,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamsSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut self.intake;
        self.shared.with_set(publish, |set, publish| {
            set.write_max_streams(publish, directionality, packet)
        })
    }

    fn supply_data_blocked<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DataBlockedSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut self.intake;
        self.shared.with_set(publish, |set, publish| {
            set.write_data_blocked(publish, packet)
        })
    }

    fn supply_stream_data_blocked<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamDataBlockedSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut self.intake;
        let Some(part) = self.shared.sender_of(stream_id) else {
            return Supplied::Open(packet);
        };
        self.shared.change_sender(
            &part,
            stream_id,
            publish,
            EventInitiator::Local,
            |end, publish| end.write_stream_data_blocked(publish, packet),
        )
    }

    fn supply_streams_blocked<Ij, Kp, W, Q, Idx>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        directionality: Directionality,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamsBlockedSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut self.intake;
        self.shared.with_set(publish, |set, publish| {
            set.write_streams_blocked(publish, directionality, packet)
        })
    }

    /// The acknowledgment of a STREAM frame's data and FIN, or of a reset
    /// frame, may make the sending part done; the others change
    /// nothing but the STREAM_DATA_BLOCKED signal's record.
    fn on_frame_delivered<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        summary: StreamSetFrameSummary,
    ) {
        let publish = &mut self.intake;
        match summary {
            StreamSetFrameSummary::Stream(summary) => self.shared.with_sender(
                summary.stream_id,
                publish,
                EventInitiator::Remote,
                |end, _| {
                    end.stream_delivered(summary);
                    end.wake_writer();
                },
            ),
            StreamSetFrameSummary::ResetStream(summary) => {
                self.shared.with_sender(
                    summary.stream_id,
                    publish,
                    EventInitiator::Remote,
                    |end, _| {
                        end.reset_delivered(summary);
                        end.wake_writer();
                    },
                );
            }
            StreamSetFrameSummary::StreamDataBlocked(summary) => {
                self.shared.with_sender(
                    summary.stream_id,
                    publish,
                    EventInitiator::Remote,
                    |end, _| {
                        end.sender
                            .on_stream_data_blocked_acknowledged(summary.maximum_stream_data);
                    },
                );
            }
            StreamSetFrameSummary::StopSending(_)
            | StreamSetFrameSummary::MaxData(_)
            | StreamSetFrameSummary::MaxStreamData(_)
            | StreamSetFrameSummary::MaxStreams(_)
            | StreamSetFrameSummary::DataBlocked(_)
            | StreamSetFrameSummary::StreamsBlocked(_) => {}
        }
    }

    /// What a lost frame carried is sent again as its owner has it now
    /// (RFC 9000 §13.3): a stream's data and FIN while they are not
    /// acknowledged; a RESET_STREAM while the sending part is not done; a
    /// STOP_SENDING while the receiving part still needs it; the limit in
    /// effect of a MAX_DATA, MAX_STREAM_DATA or MAX_STREAMS, which is never
    /// lower than the one lost, while it is still advertised; a BLOCKED
    /// frame while the sender is still blocked at its limit.
    fn on_frame_lost<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        summary: StreamSetFrameSummary,
    ) {
        let publish = &mut self.intake;
        match summary {
            StreamSetFrameSummary::Stream(summary) => self.shared.with_sender(
                summary.stream_id,
                publish,
                EventInitiator::Local,
                |end, _| end.stream_lost(summary),
            ),
            StreamSetFrameSummary::ResetStream(summary) => {
                self.shared.with_sender(
                    summary.stream_id,
                    publish,
                    EventInitiator::Local,
                    |end, _| end.reset_frame.lost(),
                );
            }
            StreamSetFrameSummary::StreamDataBlocked(summary) => {
                self.shared.with_sender(
                    summary.stream_id,
                    publish,
                    EventInitiator::Local,
                    |end, _| {
                        end.sender
                            .on_stream_data_blocked_lost(summary.maximum_stream_data);
                    },
                );
            }
            StreamSetFrameSummary::StopSending(summary) => {
                self.shared.with_receiver(
                    summary.stream_id,
                    publish,
                    EventInitiator::Local,
                    |end, _| end.receiver.on_stop_lost(),
                );
            }
            StreamSetFrameSummary::MaxStreamData(summary) => {
                self.shared.with_receiver(
                    summary.stream_id,
                    publish,
                    EventInitiator::Local,
                    |end, _| end.max_stream_data_lost(summary.maximum_stream_data),
                );
            }
            StreamSetFrameSummary::MaxData(summary) => {
                self.shared
                    .with_connection_receive(publish, |connection, _| {
                        connection.max_data_lost(summary.maximum_data);
                    });
            }
            StreamSetFrameSummary::MaxStreams(_)
            | StreamSetFrameSummary::DataBlocked(_)
            | StreamSetFrameSummary::StreamsBlocked(_) => {
                self.shared
                    .with_set(publish, |set, _| set.connection_frame_lost(&summary));
            }
        }
    }

    /// The ticket of the intent is ended and forgotten; a stream's data
    /// lets its destination fall back first. Then what is due is published
    /// again.
    fn on_intent_unfulfilled<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        key: StreamIntentKey,
        cause: Unfulfilled,
    ) {
        let publish = &mut self.intake;
        match key {
            StreamIntentKey::Stream(id) => {
                self.shared
                    .with_sender(id, publish, EventInitiator::Local, |end, publish| {
                        forget_ticket(&mut end.data, publish);
                        let _ = end.sender.on_unfulfilled(&AnyActiveLinkPath, cause);
                        // a destination left without fallback may end the stream
                        end.wake_writer();
                    })
            }
            StreamIntentKey::ResetStream(id) => {
                self.shared
                    .with_sender(id, publish, EventInitiator::Local, |end, publish| {
                        forget_ticket(&mut end.reset, publish)
                    })
            }
            StreamIntentKey::StreamDataBlocked(id) => {
                self.shared
                    .with_sender(id, publish, EventInitiator::Local, |end, publish| {
                        forget_ticket(&mut end.blocked, publish)
                    })
            }
            StreamIntentKey::StopSending(id) => {
                self.shared
                    .with_receiver(id, publish, EventInitiator::Local, |end, publish| {
                        forget_ticket(&mut end.stop, publish)
                    })
            }
            StreamIntentKey::MaxStreamData(id) => {
                self.shared
                    .with_receiver(id, publish, EventInitiator::Local, |end, publish| {
                        forget_ticket(&mut end.max_stream_data, publish)
                    })
            }
            StreamIntentKey::MaxData => {
                self.shared
                    .with_connection_receive(publish, |connection, publish| {
                        forget_ticket(&mut connection.max_data, publish);
                    })
            }
            StreamIntentKey::MaxStreams(directionality) => {
                self.shared.with_set(publish, |set, publish| {
                    forget_ticket(set.connection.max_streams.get_mut(directionality), publish);
                })
            }
            StreamIntentKey::StreamsBlocked(directionality) => {
                self.shared.with_set(publish, |set, publish| {
                    forget_ticket(
                        set.connection.streams_blocked.get_mut(directionality),
                        publish,
                    );
                });
            }
            StreamIntentKey::DataBlocked => self.shared.with_set(publish, |set, publish| {
                forget_ticket(&mut set.connection.data_blocked, publish);
            }),
        }
    }
}
