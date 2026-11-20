//! The default stream set: the streams held directly by the set, which is
//! lent to whoever acts on it, and reached only through the shared
//! connection ([`OwnedStreamSet`]).
//!
//! The set keeps what [`LockedStreamSet`](super::locked::LockedStreamSet)
//! keeps under its locks, the streams' identity, the tables of the parts,
//! the queues of the streams to accept, the end of the layer, the
//! connection's frames and its receive flow controller, as plain values:
//! whoever acts on the set has it to itself, the driver's side with a frame,
//! a supply, an acknowledgment or a loss, the application's with an
//! operation of a capability through the shared connection. Each of them
//! is lent the send strategy's publisher, publishes every intent through
//! it ([`PlacedPublisher`]), and keeps its key tickets
//! ([`PublishedTicketOf`]); whoever lent the publisher hands on what changed
//! there. The connection's send flow controller is the one the sending
//! parts share by atomic counters, as in the locked set.
//!
//! Whoever changes a part brings the intents of what it changed to what is
//! due now (`sync_intents`), as the locked set does, with the same logic
//! (`set_state`); whoever waits keeps its waker in the
//! part or the set, and whoever makes what it waits for wakes it there.
//!
//! A stream is reclaimed once each part it has is done, by whoever changed
//! the part that made it so; a part held through the shared connection
//! goes into the table of the held parts with its last result, until its
//! holder's credential comes back ([`StreamSet::reclaim_writer`],
//! [`StreamSet::reclaim_reader`]). Every part is held so, as nothing else
//! reaches it; once its credential came back, the set forgets it, and an
//! operation that names it reports an end of the layer it does not know.
//!
//! When the driver panicked, the layer's end is only marked
//! ([`StreamSet::driver_panicked`]): who waits is woken, and every
//! operation of the application reports the end without changing anything.

#[cfg(test)]
mod tests;

use alloc::sync::Arc;
use core::{
    fmt,
    marker::PhantomData,
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
};
use sakuya_wire_v1::frame::write::InFlightClass;

use bytes::{Buf, BufMut, Bytes};
use sakuya_stream_v1::{
    connection::{LayerEnd, LayerEndedError},
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::{
        AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
        ConnectionSendFlowController,
    },
    receive::stop::StopError,
    send::{
        finish::{CloseError, ResetError},
        write::{FlushError, WriteError, WriteOutcome, WriteReport, WriteWait},
    },
    send_buffer::{StreamSendBuffer, offset_map::OffsetMapStreamSendBuffer},
    send_options::{
        SendOptions,
        destination::{AnyActiveLinkPath, Unfulfilled},
        urgency::{SendUrgency, Urgency},
    },
    stream_id_ledger::{IdentifiedStream, ReceivingPartFrameType, SendingPartFrameType},
};
use sakuya_wire::var_int::VarInt;
use sakuya_wire_v1::{
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

use super::{
    FlowControlParameters, ReceivingPartFrameSnafu, ResetStreamSnafu, SendingPartFrameSnafu,
    StreamReaderCredential, StreamSet, StreamSetFacts, StreamSetFrameErrorOf, StreamSnafu,
    StreamWriterCredential, held_part_gone,
    resets::StreamResets,
    send::{
        DataBlockedSummary, MaxDataSummary, MaxStreamDataSummary, MaxStreamsSummary,
        ResetStreamSummary, StopSendingSummary, StreamDataBlockedSummary, StreamIntent,
        StreamIntentKey, StreamSetFrameSummary, StreamSummary, StreamsBlockedSummary,
    },
    set_state::{
        ChunkOf, ConnectionReceive, MarkerOf, PartDone, ReadErrorOf, ReceiveTerminationReasonOf,
        ReceivingEnd, SendingEnd, SetState, WriteLimitReasonOf, forget_ticket, max_data_frame,
        new_receiving_end, new_sending_end, part_made, part_reclaimed, read_block, read_count,
        state_after, state_before, wake_part_waiters,
    },
};
use crate::{
    feedback::InjectSummary,
    send_strategy::{IntentPublisher, PlacedPublisher, PublishOutcome, PublishTo, SendIntent},
    v1::{
        application_handles::{
            connection::{keep_waker, wake_all},
            established_layer::TryOpenStreamError,
            stream::AllAcknowledgedError,
        },
        events::{EventInitiator, NoEvents, SharedEvents},
        send_planning::{
            ComponentIntake, ComponentPublishing, HostSendStrategyTypes, PublishedTicketOf,
            StrategyPublisherForTicket, StrategyPublisherOf,
        },
    },
    write::{OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// The default stream set: the streams held directly by the set, reached
/// only through the shared connection; see the [module
/// documentation](self).
///
/// `Lc` is the type of this endpoint's reason for closing, `K` the ticket
/// of a stream intent, which the send strategy's publisher gives, `Rs` how
/// its streams are reset ([`StreamResets`]), and `P` the parameters
/// application data is sent with, by default an [`Urgency`]; all data goes
/// to [`AnyActiveLinkPath`]. Of the peer's resets it takes RESET_STREAM,
/// and RESET_STREAM_AT where its streams reset reliably (with the package
/// `sakuya_connection_reset_stream_at`).
///
/// `E` is the handle the events of its streams are given through, by
/// default [`NoEvents`], as for the locked set.
pub struct OwnedStreamSet<Lc, K, Rs: StreamResets, P = Urgency, E = NoEvents> {
    set: OwnedSetStateOf<Lc, K, Rs, P>,
    connection_receive: ConnectionReceive<K, P>,
    connection_send: Arc<AtomicConnectionSendFlowController>,
    facts: StreamSetFacts<Rs::PeerSupport>,
    config: OwnedStreamSetConfig,
    /// The handle the events of the streams are given through.
    events: E,
    /// How the layer ended, once the driver panicked: only marked, with
    /// the rest left as the panic left it.
    panic_end: Option<LayerEnd<Lc>>,
}

/// One part of one stream as the set holds it: the sending or the
/// receiving part `X`, and whether it is held through the shared
/// connection, from when it is handed out until its holder's credential
/// comes back.
struct OwnedStreamEnd<X> {
    end: X,
    held: bool,
}

impl<X> OwnedStreamEnd<X> {
    /// `end`, held from now on.
    fn held(end: X) -> Self {
        Self { end, held: true }
    }
}

/// The sending part of a stream as the set holds it.
type OwnedSending<Lc, K, Rs, P> = OwnedStreamEnd<SendingEnd<Lc, K, Rs, P>>;

/// The receiving part of a stream as the set holds it.
type OwnedReceiving<Lc, K, Rs, P> = OwnedStreamEnd<ReceivingEnd<Lc, K, Rs, P>>;

/// What the set keeps of its streams as a whole.
type OwnedSetStateOf<Lc, K, Rs, P> = SetState<
    Lc,
    K,
    P,
    OwnedSending<Lc, K, Rs, P>,
    OwnedReceiving<Lc, K, Rs, P>,
    <Rs as StreamResets>::PeerSupport,
>;

/// Where an operation finds the part it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Find {
    /// In its table: the driver's side, which takes nothing of a stream
    /// once it was reclaimed.
    Table,
    /// In its table or in the table of the held parts, while it is held:
    /// the holder's operations.
    Held,
}

/// The kind of [`OwnedStreamSet`] whose data is sent with the parameters
/// `P`, by default an [`Urgency`].
pub struct OwnedStreamSetFamily<P = Urgency>(PhantomData<fn() -> P>);

impl<P> fmt::Debug for OwnedStreamSetFamily<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedStreamSetFamily")
    }
}

impl<P> super::StreamSetFamily for OwnedStreamSetFamily<P>
where
    P: Clone + PartialEq + Default + SendUrgency + 'static,
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>:
        StreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
{
    type Config = OwnedStreamSetConfig;
    type SendParameters = P;
    type Set<Lc, I: HostSendStrategyTypes, X: StreamResets, E: SharedEvents + Clone + 'static>
        = OwnedStreamSet<Lc, <Self as ComponentPublishing<I, StreamIntent<P>>>::Ticket, X, P, E>
    where
        Self: ComponentPublishing<I, StreamIntent<P>>;
}

/// The set is held only through the shared connection: it publishes
/// through the strategy's publisher it is lent, and keeps that publisher's
/// tickets, for any strategy types.
impl<I, P> ComponentPublishing<I, StreamIntent<P>> for OwnedStreamSetFamily<P>
where
    I: HostSendStrategyTypes,
    StrategyPublisherOf<I>: PublishOutcome<StreamIntent<P>, AnyActiveLinkPath>,
{
    type Ticket = PublishedTicketOf<I, StreamIntent<P>>;
    type Intake = ();
}

/// It asks the core for nothing; `Idx` is where the publisher takes the
/// stream intents.
impl<I, P, Idx> ComponentIntake<I, StreamIntent<P>, Idx> for OwnedStreamSetFamily<P>
where
    I: HostSendStrategyTypes,
    StreamIntent<P>: SendIntent,
    StrategyPublisherOf<I>: PublishTo<StreamIntent<P>, AnyActiveLinkPath, Idx>,
{
    fn intake(_: &mut I::Strategy) -> Self::Intake {}
}

/// What [`OwnedStreamSet`] is configured with: the error codes of the
/// resets and STOP_SENDING frames the default policies of its streams send
/// by themselves. Each is 0 by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnedStreamSetConfig {
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

impl<Lc, K, Rs: StreamResets, P, E> fmt::Debug for OwnedStreamSet<Lc, K, Rs, P, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedStreamSet").finish_non_exhaustive()
    }
}

/// The table entry of `id` among `table` and `held`, as `find` says.
fn found<'a, X>(
    table: &'a mut alloc::collections::BTreeMap<StreamId, OwnedStreamEnd<X>>,
    held: &'a mut alloc::collections::BTreeMap<StreamId, OwnedStreamEnd<X>>,
    id: StreamId,
    find: Find,
) -> Option<&'a mut X> {
    match find {
        Find::Table => table.get_mut(&id).map(|part| &mut part.end),
        Find::Held => table
            .get_mut(&id)
            .or_else(|| held.get_mut(&id))
            .filter(|part| part.held)
            .map(|part| &mut part.end),
    }
}

/// Everything the set does, over whatever it publishes through, `H`: the
/// strategy's publisher placed for the stream intents when it is lent one
/// ([`StreamSet`]), or anything else that publishes them.
impl<Lc, K, Rs: StreamResets, P, E> OwnedStreamSet<Lc, K, Rs, P, E>
where
    P: Clone + PartialEq + Default + SendUrgency,
    E: SharedEvents,
{
    /// The set of a layer, as [`StreamSet::new`] makes it.
    fn made(
        facts: StreamSetFacts<Rs::PeerSupport>,
        config: OwnedStreamSetConfig,
        events: E,
    ) -> Self {
        Self {
            set: SetState::new(&facts),
            connection_receive: ConnectionReceive {
                flow: ConnectionReceiveFlowController::new(
                    facts.granted_to_peer.initial_max_data.get(),
                ),
                max_data: None,
                max_data_lost: false,
                ended: false,
            },
            connection_send: Arc::new(AtomicConnectionSendFlowController::new(
                facts.granted_by_peer.initial_max_data.get(),
            )),
            facts,
            config,
            events,
            panic_end: None,
        }
    }

    // ---- changing a part ----

    /// Change the sending part of `id`, found as `find` says, with
    /// `change`, which is given the handle of the events and `publish` too;
    /// bring its intents to what is due then, give the change of its state
    /// on the action of `trigger`, and reclaim the stream if it is done.
    /// `None` when the part is not found.
    fn change_sending<H, R>(
        &mut self,
        id: StreamId,
        find: Find,
        publish: &mut H,
        trigger: EventInitiator,
        change: impl FnOnce(&mut SendingEnd<Lc, K, Rs, P>, &E, &mut H) -> R,
    ) -> Option<R>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let Self { set, events, .. } = self;
        let end = found(&mut set.senders, &mut set.held_senders, id, find)?;
        let before = state_before(events, end);
        let result = change(end, events, publish);
        end.sync_intents(publish);
        state_after(events, id, before, end, trigger);
        self.reclaim_if_done(id, publish);
        Some(result)
    }

    /// Change the receiving part of `id`, as
    /// [`change_sending`](Self::change_sending) the sending part; `change`
    /// is also given what the receive flow controller is kept with. When
    /// `releases`, what the stream released is reported to the controller
    /// before the intents are brought to what is due, the MAX_DATA one
    /// first.
    #[allow(clippy::too_many_arguments)] // the change, and where it goes
    fn change_receiving<H, R>(
        &mut self,
        id: StreamId,
        find: Find,
        releases: bool,
        publish: &mut H,
        trigger: EventInitiator,
        change: impl FnOnce(&mut ReceivingEnd<Lc, K, Rs, P>, &E, &mut H) -> R,
    ) -> Option<R>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let Self {
            set,
            connection_receive,
            events,
            ..
        } = self;
        let end = found(&mut set.receivers, &mut set.held_receivers, id, find)?;
        let before = state_before(events, end);
        let result = change(end, events, publish);
        if releases {
            let released = end.receiver.report_release(&mut connection_receive.flow);
            // invariant: every stream of the set accounts its data with the
            // set's one controller
            debug_assert!(
                released.is_ok(),
                "a stream releases what it accounted: {released:?}"
            );
            connection_receive.sync_intents(publish);
        }
        end.sync_intents(id, publish);
        state_after(events, id, before, end, trigger);
        self.reclaim_if_done(id, publish);
        Some(result)
    }

    /// The panic's end, if the driver panicked, as an operation of the
    /// application reports it.
    fn panicked(&self) -> Result<(), LayerEndedError<Lc>> {
        match &self.panic_end {
            Some(end) => Err(LayerEndedError::new(end.clone())),
            None => Ok(()),
        }
    }

    /// Change the sending part of `held` for an operation of its holder, as
    /// [`change_sending`](Self::change_sending) does, on this side's action.
    /// Once the driver panicked, the end it marked, and nothing changes;
    /// once the credential came back, an end of the layer it does not
    /// know.
    fn change_held_sending<H, R>(
        &mut self,
        id: StreamId,
        publish: &mut H,
        change: impl FnOnce(&mut SendingEnd<Lc, K, Rs, P>, &E, &mut H) -> R,
    ) -> Result<R, LayerEndedError<Lc>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        self.panicked()?;
        self.change_sending(id, Find::Held, publish, EventInitiator::Local, change)
            .ok_or_else(|| held_part_gone(Some(id)))
    }

    /// Change the receiving part of `held` for an operation of its holder,
    /// as [`change_held_sending`](Self::change_held_sending) the sending
    /// part; what the stream released is reported.
    fn change_held_receiving<H, R>(
        &mut self,
        id: StreamId,
        publish: &mut H,
        change: impl FnOnce(&mut ReceivingEnd<Lc, K, Rs, P>, &E, &mut H) -> R,
    ) -> Result<R, LayerEndedError<Lc>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        self.panicked()?;
        self.change_receiving(id, Find::Held, true, publish, EventInitiator::Local, change)
            .ok_or_else(|| held_part_gone(Some(id)))
    }

    /// Reclaim the stream `id` if each part it has is done: its parts leave
    /// the tables, each giving its last state, and the ledger records the
    /// reclaim, which lets the peer open one more stream of the type when
    /// the stream is the peer's; a part that is held goes into the table of
    /// the held parts. Then the connection's intents are brought to what is
    /// due. Nothing is reclaimed once the layer ended or the driver
    /// panicked, nor a stream reclaimed already.
    fn reclaim_if_done<H>(&mut self, id: StreamId, publish: &mut H)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        if self.panic_end.is_some() || self.set.end.is_some() {
            return;
        }
        let set = &mut self.set;
        let sending = set.senders.get(&id);
        let receiving = set.receivers.get(&id);
        // invariant: a stream gets every part it has when it is created, and
        // the parts leave the tables together
        debug_assert!(
            id.directionality() == Directionality::Unidirectional
                || sending.is_some() == receiving.is_some(),
            "a bidirectional stream {id} has one part in the tables"
        );
        if sending.is_none() && receiving.is_none()
            || !sending.is_none_or(|part| part.end.is_done())
            || !receiving.is_none_or(|part| part.end.is_done())
        {
            return;
        }
        if let Some(part) = set.senders.remove(&id) {
            part_reclaimed(&self.events, id, &part.end);
            if part.held {
                set.held_senders.insert(id, part);
            }
        }
        if let Some(part) = set.receivers.remove(&id) {
            part_reclaimed(&self.events, id, &part.end);
            if part.held {
                set.held_receivers.insert(id, part);
            }
        }
        let reclaimed = set.ledger.reclaim(id);
        // invariant: a stream in the tables was opened and created, and is
        // reclaimed only here, when it leaves them
        debug_assert!(
            reclaimed.is_ok(),
            "stream {id} is reclaimed once: {reclaimed:?}"
        );
        set.sync_intents(publish);
    }

    // ---- the streams' identity ----

    /// Make the parts of `id`, a stream the peer opened that a frame just
    /// created, held from now on, and queue it to be accepted. A
    /// bidirectional stream gets both parts, a unidirectional one its
    /// receiving part. Each part made is an event of the peer's.
    fn create_peer_stream(&mut self, id: StreamId) {
        let receiving = new_receiving_end(&self.facts, id, self.config.receive_abandon_code);
        part_made(&self.events, id, &receiving, EventInitiator::Remote);
        self.set
            .receivers
            .insert(id, OwnedStreamEnd::held(receiving));
        match id.directionality() {
            Directionality::Bidirectional => {
                let sending = self.new_sending(id);
                part_made(&self.events, id, &sending, EventInitiator::Remote);
                self.set.senders.insert(id, OwnedStreamEnd::held(sending));
                self.set.accept_bidirectional.push_back(id);
            }
            Directionality::Unidirectional => self.set.accept_unidirectional.push_back(id),
        }
        wake_all(self.set.accept_wakers.get_mut(id.directionality()));
    }

    /// Make the parts of `id`, a stream this side opens, held from now on:
    /// a bidirectional one gets both, a unidirectional one its sending
    /// part. Each part made is an event of this side's.
    fn create_local_stream(&mut self, id: StreamId) {
        let sending = self.new_sending(id);
        part_made(&self.events, id, &sending, EventInitiator::Local);
        self.set.senders.insert(id, OwnedStreamEnd::held(sending));
        if id.directionality() == Directionality::Bidirectional {
            let receiving = new_receiving_end(&self.facts, id, self.config.receive_abandon_code);
            part_made(&self.events, id, &receiving, EventInitiator::Local);
            self.set
                .receivers
                .insert(id, OwnedStreamEnd::held(receiving));
        }
    }

    /// The sending part of `id`, as it is made.
    fn new_sending(&self, id: StreamId) -> SendingEnd<Lc, K, Rs, P> {
        new_sending_end(
            &self.facts,
            &self.set.granted_by_peer,
            id,
            self.config.send_abandon_code,
            self.config.destination_exhausted_code,
            &self.connection_send,
        )
    }

    /// Whether a frame of `frame_type` for the receiving part of `id`, which
    /// passed the checks of the streams' identity, reaches its part: made
    /// if the frame creates the stream; `false` when the frame is to be
    /// ignored, as the stream was reclaimed or the layer ended.
    fn identify_receiving(
        &mut self,
        id: StreamId,
        frame_type: ReceivingPartFrameType,
    ) -> Result<bool, StreamSetFrameErrorOf<Rs>> {
        if self.set.end.is_some() {
            return Ok(false);
        }
        match self
            .set
            .ledger
            .on_receiving_part_frame(id, frame_type)
            .context(ReceivingPartFrameSnafu)?
        {
            IdentifiedStream::Created => self.create_peer_stream(id),
            IdentifiedStream::Existing => {}
            IdentifiedStream::Reclaimed => return Ok(false),
        }
        // invariant: a stream gets its parts when it is created, and leaves
        // the tables only when it is reclaimed
        debug_assert!(
            self.set.receivers.contains_key(&id),
            "stream {id} has no receiving part"
        );
        Ok(true)
    }

    /// Whether a frame of `frame_type` for the sending part of `id` reaches
    /// its part, as [`identify_receiving`](Self::identify_receiving) for the
    /// receiving part.
    fn identify_sending(
        &mut self,
        id: StreamId,
        frame_type: SendingPartFrameType,
    ) -> Result<bool, StreamSetFrameErrorOf<Rs>> {
        if self.set.end.is_some() {
            return Ok(false);
        }
        match self
            .set
            .ledger
            .on_sending_part_frame(id, frame_type)
            .context(SendingPartFrameSnafu)?
        {
            // a bidirectional stream of the peer, opened by a frame for its
            // sending part (RFC 9000 §3.2, §19.5, §19.10)
            IdentifiedStream::Created => self.create_peer_stream(id),
            IdentifiedStream::Existing => {}
            IdentifiedStream::Reclaimed => return Ok(false),
        }
        // invariant: as for the receiving part
        debug_assert!(
            self.set.senders.contains_key(&id),
            "stream {id} has no sending part"
        );
        Ok(true)
    }

    /// Take a frame of the peer for the receiving part of `id`, which
    /// reached it ([`identify_receiving`](Self::identify_receiving)), with
    /// `take`, given the part and the receive flow controller; then bring
    /// the part's intents to what is due, wake its readers, give the change
    /// of its state as the peer's, and reclaim the stream if it is done. A
    /// frame the part refuses changes nothing more.
    fn take_receiving_frame<H>(
        &mut self,
        id: StreamId,
        publish: &mut H,
        take: impl FnOnce(
            &mut ReceivingEnd<Lc, K, Rs, P>,
            &mut ConnectionReceiveFlowController,
        ) -> Result<(), StreamSetFrameErrorOf<Rs>>,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let Self {
            set,
            connection_receive,
            events,
            ..
        } = self;
        let Some(part) = set.receivers.get_mut(&id) else {
            return Ok(());
        };
        let end = &mut part.end;
        let before = state_before(events, end);
        take(end, &mut connection_receive.flow)?;
        end.sync_intents(id, publish);
        end.wake_reader();
        state_after(events, id, before, end, EventInitiator::Remote);
        self.reclaim_if_done(id, publish);
        Ok(())
    }

    // ---- the driver's side ----

    fn on_stream_frame_through<H>(
        &mut self,
        publish: &mut H,
        level: EncryptionLevel,
        frame: StreamFrame<Bytes>,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let id = frame.stream_id().get();
        if !self.identify_receiving(id, ReceivingPartFrameType::Stream)? {
            return Ok(());
        }
        self.take_receiving_frame(id, publish, |end, flow| {
            end.receiver
                .on_stream_frame(frame, flow)
                .context(StreamSnafu)?;
            if level == EncryptionLevel::ZeroRtt {
                end.receiver.mark_received_zero_rtt();
            }
            Ok(())
        })
    }

    fn on_reset_stream_through<H>(
        &mut self,
        publish: &mut H,
        frame: ResetStreamFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let id = frame.stream_id().get();
        if !self.identify_receiving(id, ReceivingPartFrameType::ResetStream)? {
            return Ok(());
        }
        self.take_receiving_frame(id, publish, |end, flow| {
            Rs::on_reset_stream(&mut end.receiver, frame, flow).context(ResetStreamSnafu)
        })
    }

    fn on_stop_sending_through<H>(
        &mut self,
        publish: &mut H,
        frame: StopSendingFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let id = frame.stream_id().get();
        if self.identify_sending(id, SendingPartFrameType::StopSending)? {
            self.change_sending(
                id,
                Find::Table,
                publish,
                EventInitiator::Remote,
                |end, _, _| {
                    end.sender
                        .on_stop_sending(frame.application_error_code().get());
                    end.wake_writer();
                },
            );
        }
        Ok(())
    }

    /// A larger limit clears the DATA_BLOCKED signal of a lower one.
    fn on_max_data_through<H>(&mut self, publish: &mut H, frame: MaxDataFrame)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        self.connection_send.on_max_data(frame.maximum_data().get());
        let limit = self.connection_send.limit();
        self.set
            .connection
            .data_blocked_signal
            .on_limit_raised(limit);
        self.set.sync_intents(publish);
    }

    fn on_max_stream_data_through<H>(
        &mut self,
        publish: &mut H,
        frame: MaxStreamDataFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let id = frame.stream_id().get();
        if self.identify_sending(id, SendingPartFrameType::MaxStreamData)? {
            self.change_sending(
                id,
                Find::Table,
                publish,
                EventInitiator::Remote,
                |end, _, _| {
                    end.sender
                        .on_max_stream_data(frame.maximum_stream_data().get());
                    end.wake_writer();
                },
            );
        }
        Ok(())
    }

    fn on_max_streams_through<H>(&mut self, publish: &mut H, frame: MaxStreamsFrame)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        self.set.on_max_streams(&frame);
        self.set.sync_intents(publish);
    }

    fn on_stream_data_blocked_through<H>(
        &mut self,
        publish: &mut H,
        frame: StreamDataBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let id = frame.stream_id().get();
        if self.identify_receiving(id, ReceivingPartFrameType::StreamDataBlocked)? {
            self.change_receiving(
                id,
                Find::Table,
                false,
                publish,
                EventInitiator::Remote,
                |end, _, _| {
                    end.receiver
                        .on_stream_data_blocked(frame.maximum_stream_data().get());
                },
            );
        }
        Ok(())
    }

    fn peer_transport_parameters_known_through<H>(
        &mut self,
        publish: &mut H,
        granted: FlowControlParameters,
        reset_support: Rs::PeerSupport,
    ) where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        if self.set.end.is_some() {
            return;
        }
        self.set.peer_parameters_known(&granted, reset_support);
        self.on_max_data_through(publish, max_data_frame(granted.initial_max_data.get()));
        let senders: Vec<StreamId> = self.set.senders.keys().copied().collect();
        for id in senders {
            let limit = self.facts.send_limit(&granted, id);
            self.change_sending(
                id,
                Find::Table,
                publish,
                EventInitiator::Remote,
                |end, _, _| {
                    end.sender.on_max_stream_data(limit);
                    end.wake_writer();
                },
            );
        }
    }

    fn layer_ended_now<H>(&mut self, publish: &mut H, end: LayerEnd<Lc>)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        if !self.set.layer_ended(end.clone(), publish) {
            return;
        }
        self.connection_receive.layer_ended(publish);
        for part in self.set.senders.values_mut() {
            part.end.layer_ended(end.clone(), publish);
        }
        for part in self.set.receivers.values_mut() {
            part.end.layer_ended(end.clone(), publish);
        }
    }

    fn driver_panicked_now(&mut self, end: LayerEnd<Lc>) {
        if self.panic_end.is_some() {
            return;
        }
        self.panic_end = Some(end);
        self.set.wake_waiting();
        for part in self.set.senders.values_mut() {
            wake_part_waiters(core::mem::take(&mut part.end.writer));
        }
        for part in self.set.receivers.values_mut() {
            wake_part_waiters(core::mem::take(&mut part.end.reader));
        }
    }

    // ---- opening, accepting and handing back ----

    fn open_held_through<H>(
        &mut self,
        publish: &mut H,
        directionality: Directionality,
        waker: Option<&Waker>,
    ) -> Result<StreamId, TryOpenStreamError<Lc>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        // once the driver panicked, the set is not changed any more
        if let Some(end) = self.panic_end.as_ref().or(self.set.end.as_ref()) {
            return Err(LayerEndedError::new(end.clone()).into());
        }
        let opened = match self.set.ledger.open_local(directionality) {
            Ok(id) => {
                self.create_local_stream(id);
                Ok(id)
            }
            Err(_) => {
                if let Some(waker) = waker {
                    keep_waker(self.set.open_wakers.get_mut(directionality), waker);
                }
                Err(TryOpenStreamError::AtLimit)
            }
        };
        self.set.sync_intents(publish);
        opened
    }

    fn poll_accept_now(
        &mut self,
        cx: &mut Context<'_>,
        directionality: Directionality,
    ) -> Poll<Result<StreamId, LayerEndedError<Lc>>> {
        if let Some(end) = self.panic_end.as_ref().or(self.set.end.as_ref()) {
            return Poll::Ready(Err(LayerEndedError::new(end.clone())));
        }
        let queue = match directionality {
            Directionality::Bidirectional => &mut self.set.accept_bidirectional,
            Directionality::Unidirectional => &mut self.set.accept_unidirectional,
        };
        match queue.pop_front() {
            Some(id) => {
                // invariant: a stream of the peer enters the queue when its
                // parts are made, and leaves the tables only when it is
                // reclaimed, which needs its reader to be done with it
                debug_assert!(
                    self.set.receivers.contains_key(&id),
                    "stream {id} to accept has no receiving part"
                );
                Poll::Ready(Ok(id))
            }
            None => {
                keep_waker(self.set.accept_wakers.get_mut(directionality), cx.waker());
                Poll::Pending
            }
        }
    }

    /// The holder of the sending part of `id` gave its credential back:
    /// the writer gives the stream up, the part is no longer held, and the
    /// stream is reclaimed if it is done; a part reclaimed already leaves
    /// the table of the held parts. Once the driver panicked, nothing
    /// changes.
    fn reclaim_writer_through<H>(&mut self, publish: &mut H, id: StreamId)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        if self.panic_end.is_some() {
            return;
        }
        if let Some(mut part) = self.set.held_senders.remove(&id) {
            part.end.give_up();
            return;
        }
        // its part may be reclaimed by giving up, and is then not kept
        if let Some(part) = self.set.senders.get_mut(&id) {
            part.held = false;
        }
        self.change_sending(
            id,
            Find::Table,
            publish,
            EventInitiator::Local,
            |end, _, _| {
                end.give_up();
            },
        );
    }

    /// The holder of the receiving part of `id` gave its credential back,
    /// as [`reclaim_writer_through`](Self::reclaim_writer_through) for the
    /// sending part.
    fn reclaim_reader_through<H>(&mut self, publish: &mut H, id: StreamId)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        if self.panic_end.is_some() {
            return;
        }
        if let Some(mut part) = self.set.held_receivers.remove(&id) {
            part.end.give_up();
            return;
        }
        // its part may be reclaimed by giving up, and is then not kept
        if let Some(part) = self.set.receivers.get_mut(&id) {
            part.held = false;
        }
        self.change_receiving(
            id,
            Find::Table,
            true,
            publish,
            EventInitiator::Local,
            |end, _, _| end.give_up(),
        );
    }

    // ---- the application's operations ----

    #[allow(clippy::too_many_arguments)] // the write's own, and the publisher
    #[allow(clippy::type_complexity)] // the write's result
    fn poll_write_through<H, B: Buf + ?Sized>(
        &mut self,
        publish: &mut H,
        id: StreamId,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &P,
        destination: &AnyActiveLinkPath,
    ) -> Poll<Result<WriteReport, WriteError<WriteLimitReasonOf<Rs, P>, Lc>>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let marker = SendOptions::new(parameters.clone(), *destination);
        loop {
            let outcome = match self.change_held_sending(id, publish, |end, events, _| {
                end.write_from(events, input, &marker, cx.waker())
            }) {
                Ok(outcome) => outcome,
                Err(ended) => return Poll::Ready(Err(ended.into())),
            };
            match outcome {
                Ok(WriteOutcome::Written(report)) => return Poll::Ready(Ok(report)),
                Err(error) => return Poll::Ready(Err(error)),
                Ok(WriteOutcome::Wait(WriteWait::ConnectionCredit)) => {}
                Ok(WriteOutcome::Wait(_)) => return Poll::Pending,
            }
            // registered before looking again, so that credit given back
            // in between wakes it
            let connection = &self.connection_send;
            connection.register_credit_waker(cx.waker());
            let limit = connection.limit();
            self.set
                .connection
                .data_blocked_signal
                .on_write_blocked(limit);
            self.set.sync_intents(publish);
            if self.connection_send.available() == VarInt::ZERO {
                return Poll::Pending;
            }
        }
    }

    fn poll_read_into_through<H, O: BufMut + ?Sized>(
        &mut self,
        publish: &mut H,
        id: StreamId,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, ReadErrorOf<Lc, Rs>>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let read = self.change_held_receiving(id, publish, |end, events, _| {
            end.poll_read_with(id, events, cx.waker(), |end| {
                end.receiver.read_into(destination)
            })
        });
        read_count(read.unwrap_or_else(|ended| Poll::Ready(Err(ended.into()))))
    }

    fn poll_read_chunk_through<H>(
        &mut self,
        publish: &mut H,
        id: StreamId,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<ChunkOf>, ReadErrorOf<Lc, Rs>>>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let read = self.change_held_receiving(id, publish, |end, events, _| {
            end.poll_read_with(id, events, cx.waker(), |end| {
                end.receiver.read_chunk(maximum)
            })
        });
        read_block(read.unwrap_or_else(|ended| Poll::Ready(Err(ended.into()))))
    }

    /// The sending part of `id` for an operation of its holder that changes
    /// nothing but the wakers kept: once the driver panicked, the end it
    /// marked; once the credential came back, an end it does not know.
    fn held_sending(
        &mut self,
        id: StreamId,
    ) -> Result<&mut SendingEnd<Lc, K, Rs, P>, LayerEndedError<Lc>> {
        self.panicked()?;
        found(
            &mut self.set.senders,
            &mut self.set.held_senders,
            id,
            Find::Held,
        )
        .ok_or_else(|| held_part_gone(Some(id)))
    }

    // ---- the frames written, and what becomes of them ----

    fn supply_stream_through<H, W, Q, Idx>(
        &mut self,
        publish: &mut H,
        stream_id: StreamId,
        urgency: Urgency,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamSummary, Idx>,
        Q: PacketPosition,
    {
        let mut packet = Some(packet);
        let supplied = self.change_sending(
            stream_id,
            Find::Table,
            publish,
            EventInitiator::Local,
            |end, _, _| {
                packet
                    .take()
                    .map(|packet| end.write_stream(urgency, packet))
            },
        );
        supplied
            .flatten()
            .or_else(|| packet.map(Supplied::Open))
            .unwrap_or_else(|| unreachable!("the packet is either written into or given back"))
    }

    fn on_frame_delivered_through<H>(&mut self, publish: &mut H, summary: StreamSetFrameSummary)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let trigger = EventInitiator::Remote;
        match summary {
            StreamSetFrameSummary::Stream(summary) => {
                self.change_sending(
                    summary.stream_id,
                    Find::Table,
                    publish,
                    trigger,
                    |end, _, _| {
                        end.stream_delivered(summary);
                        end.wake_writer();
                    },
                );
            }
            StreamSetFrameSummary::ResetStream(summary) => {
                self.change_sending(
                    summary.stream_id,
                    Find::Table,
                    publish,
                    trigger,
                    |end, _, _| {
                        end.reset_delivered(summary);
                        end.wake_writer();
                    },
                );
            }
            StreamSetFrameSummary::StreamDataBlocked(summary) => {
                self.change_sending(
                    summary.stream_id,
                    Find::Table,
                    publish,
                    trigger,
                    |end, _, _| {
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

    fn on_frame_lost_through<H>(&mut self, publish: &mut H, summary: StreamSetFrameSummary)
    where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let trigger = EventInitiator::Local;
        match summary {
            StreamSetFrameSummary::Stream(summary) => {
                self.change_sending(
                    summary.stream_id,
                    Find::Table,
                    publish,
                    trigger,
                    |end, _, _| {
                        end.stream_lost(summary);
                    },
                );
            }
            StreamSetFrameSummary::ResetStream(summary) => {
                self.change_sending(
                    summary.stream_id,
                    Find::Table,
                    publish,
                    trigger,
                    |end, _, _| {
                        end.reset_frame.lost();
                    },
                );
            }
            StreamSetFrameSummary::StreamDataBlocked(summary) => {
                self.change_sending(
                    summary.stream_id,
                    Find::Table,
                    publish,
                    trigger,
                    |end, _, _| {
                        end.sender
                            .on_stream_data_blocked_lost(summary.maximum_stream_data);
                    },
                );
            }
            StreamSetFrameSummary::StopSending(summary) => {
                self.change_receiving(
                    summary.stream_id,
                    Find::Table,
                    false,
                    publish,
                    trigger,
                    |end, _, _| end.receiver.on_stop_lost(),
                );
            }
            StreamSetFrameSummary::MaxStreamData(summary) => {
                self.change_receiving(
                    summary.stream_id,
                    Find::Table,
                    false,
                    publish,
                    trigger,
                    |end, _, _| end.max_stream_data_lost(summary.maximum_stream_data),
                );
            }
            StreamSetFrameSummary::MaxData(summary) => {
                self.connection_receive.max_data_lost(summary.maximum_data);
                self.connection_receive.sync_intents(publish);
            }
            StreamSetFrameSummary::MaxStreams(_)
            | StreamSetFrameSummary::DataBlocked(_)
            | StreamSetFrameSummary::StreamsBlocked(_) => {
                self.set.connection_frame_lost(&summary);
                self.set.sync_intents(publish);
            }
        }
    }

    /// The ticket of the intent is withdrawn and forgotten; a
    /// stream's data lets its destination fall back first. Then what is due
    /// is published again.
    fn on_intent_unfulfilled_through<H>(
        &mut self,
        publish: &mut H,
        key: StreamIntentKey,
        cause: Unfulfilled,
    ) where
        H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    {
        let trigger = EventInitiator::Local;
        match key {
            StreamIntentKey::Stream(id) => {
                self.change_sending(id, Find::Table, publish, trigger, |end, _, publish| {
                    forget_ticket(&mut end.data, publish);
                    let _ = end.sender.on_unfulfilled(&AnyActiveLinkPath, cause);
                    // a destination left without fallback may end the stream
                    end.wake_writer();
                });
            }
            StreamIntentKey::ResetStream(id) => {
                self.change_sending(id, Find::Table, publish, trigger, |end, _, publish| {
                    forget_ticket(&mut end.reset, publish);
                });
            }
            StreamIntentKey::StreamDataBlocked(id) => {
                self.change_sending(id, Find::Table, publish, trigger, |end, _, publish| {
                    forget_ticket(&mut end.blocked, publish);
                });
            }
            StreamIntentKey::StopSending(id) => {
                self.change_receiving(
                    id,
                    Find::Table,
                    false,
                    publish,
                    trigger,
                    |end, _, publish| {
                        forget_ticket(&mut end.stop, publish);
                    },
                );
            }
            StreamIntentKey::MaxStreamData(id) => {
                self.change_receiving(
                    id,
                    Find::Table,
                    false,
                    publish,
                    trigger,
                    |end, _, publish| {
                        forget_ticket(&mut end.max_stream_data, publish);
                    },
                );
            }
            StreamIntentKey::MaxData => {
                forget_ticket(&mut self.connection_receive.max_data, publish);
                self.connection_receive.sync_intents(publish);
            }
            StreamIntentKey::MaxStreams(directionality) => {
                forget_ticket(
                    self.set.connection.max_streams.get_mut(directionality),
                    publish,
                );
                self.set.sync_intents(publish);
            }
            StreamIntentKey::StreamsBlocked(directionality) => {
                forget_ticket(
                    self.set.connection.streams_blocked.get_mut(directionality),
                    publish,
                );
                self.set.sync_intents(publish);
            }
            StreamIntentKey::DataBlocked => {
                forget_ticket(&mut self.set.connection.data_blocked, publish);
                self.set.sync_intents(publish);
            }
        }
    }
}

/// The publisher `publish` placed for the stream intents of the parameters
/// `P` at `Ij`.
fn placed<R, P, Ij>(publish: &mut R) -> PlacedPublisher<'_, R, StreamIntent<P>, Ij> {
    PlacedPublisher::new(publish)
}

/// `P` is a send parameter the default send buffer orders data by. The
/// peer's frames and the acknowledgments of what this side sent are the
/// peer's actions on a part; what this side writes, the losses it declares
/// and the ends of the strategy's intents are this side's.
///
/// Everything it publishes goes through the strategy's publisher it is
/// lent, placed for the stream intents at `Ij`; the tickets it keeps are
/// the publisher's.
impl<Lc, I, Rs: StreamResets, P, E> StreamSet<Lc, I, Rs>
    for OwnedStreamSet<Lc, PublishedTicketOf<I, StreamIntent<P>>, Rs, P, E>
where
    I: HostSendStrategyTypes,
    StrategyPublisherOf<I>: PublishOutcome<StreamIntent<P>, AnyActiveLinkPath>,
    P: Clone + PartialEq + Default + SendUrgency,
    E: SharedEvents,
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>:
        StreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
{
    /// Nothing of it is held apart from the connection.
    type Handle = ();
    type Config = OwnedStreamSetConfig;
    type SendParameters = P;
    type Events = E;
    type Intake = ();
    type WriteLimitReason = WriteLimitReasonOf<Rs, P>;
    type ReceiveTerminationReason = ReceiveTerminationReasonOf<Rs>;
    type Chunk = ChunkOf;

    fn new(
        facts: StreamSetFacts<Rs::PeerSupport>,
        config: OwnedStreamSetConfig,
        events: E,
        (): (),
    ) -> Self {
        Self::made(facts, config, events)
    }

    fn handle(&self) {}

    /// A STREAM frame in a 0-RTT packet marks its stream once the stream
    /// took it.
    fn on_stream_frame<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        level: EncryptionLevel,
        frame: StreamFrame<Bytes>,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_stream_frame_through(&mut placed::<_, P, Ij>(publish), level, frame)
    }

    fn on_reset_stream<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: ResetStreamFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_reset_stream_through(&mut placed::<_, P, Ij>(publish), frame)
    }

    fn on_reset_frame<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: Rs::ResetFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        let id = Rs::reset_frame_stream_id(&frame);
        if !self.identify_receiving(id, Rs::reset_frame_type(&frame))? {
            return Ok(());
        }
        self.take_receiving_frame(id, &mut placed::<_, P, Ij>(publish), |end, flow| {
            Rs::on_reset_frame(&mut end.receiver, frame, flow).context(ResetStreamSnafu)
        })
    }

    fn on_stop_sending<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: StopSendingFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_stop_sending_through(&mut placed::<_, P, Ij>(publish), frame)
    }

    /// A larger limit clears the DATA_BLOCKED signal of a lower one.
    fn on_max_data<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: MaxDataFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_max_data_through(&mut placed::<_, P, Ij>(publish), frame);
        Ok(())
    }

    fn on_max_stream_data<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: MaxStreamDataFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_max_stream_data_through(&mut placed::<_, P, Ij>(publish), frame)
    }

    /// A limit that does not grow is ignored (RFC 9000 §19.11).
    fn on_max_streams<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: MaxStreamsFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_max_streams_through(&mut placed::<_, P, Ij>(publish), frame);
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
        publish: &mut StrategyPublisherOf<I>,
        frame: StreamDataBlockedFrame,
    ) -> Result<(), StreamSetFrameErrorOf<Rs>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_stream_data_blocked_through(&mut placed::<_, P, Ij>(publish), frame)
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

    fn peer_transport_parameters_known<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        granted_by_peer: FlowControlParameters,
        peer_reset_support: Rs::PeerSupport,
    ) where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.peer_transport_parameters_known_through(
            &mut placed::<_, P, Ij>(publish),
            granted_by_peer,
            peer_reset_support,
        );
    }

    /// The end is kept first, and each part hears of it; only the first
    /// end is kept. Every intent is withdrawn: nothing of the layer is sent
    /// any more.
    fn layer_ended<Ij, Kp>(&mut self, publish: &mut StrategyPublisherOf<I>, end: LayerEnd<Lc>)
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.layer_ended_now(&mut placed::<_, P, Ij>(publish), end);
    }

    /// The end is marked, and who waits is woken; nothing else changes.
    fn driver_panicked(&mut self, end: LayerEnd<Lc>) {
        self.driver_panicked_now(end);
    }

    fn open_held<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        directionality: Directionality,
        waker: Option<&Waker>,
    ) -> Result<StreamId, TryOpenStreamError<Lc>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.open_held_through(&mut placed::<_, P, Ij>(publish), directionality, waker)
    }

    fn poll_accept_held(
        &mut self,
        cx: &mut Context<'_>,
        directionality: Directionality,
    ) -> Poll<Result<StreamId, LayerEndedError<Lc>>> {
        self.poll_accept_now(cx, directionality)
    }

    /// The credential names the stream whose writer is let go now.
    fn reclaim_writer<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        credential: StreamWriterCredential,
    ) where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.reclaim_writer_through(&mut placed::<_, P, Ij>(publish), credential.stream_id());
    }

    /// As [`reclaim_writer`](Self::reclaim_writer) for the reader.
    fn reclaim_reader<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        credential: StreamReaderCredential,
    ) where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.reclaim_reader_through(&mut placed::<_, P, Ij>(publish), credential.stream_id());
    }

    fn poll_write<Ij, Kp, B: Buf + ?Sized>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamWriterCredential,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &P,
        destination: &AnyActiveLinkPath,
    ) -> Poll<Result<WriteReport, WriteError<WriteLimitReasonOf<Rs, P>, Lc>>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.poll_write_through(
            &mut placed::<_, P, Ij>(publish),
            held.stream_id(),
            cx,
            input,
            parameters,
            destination,
        )
    }

    /// The end moves to the transport when the close ends a stream that
    /// was open; closing again moves nothing.
    fn close<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamWriterCredential,
    ) -> Result<(), CloseError<Lc>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.change_held_sending(
            held.stream_id(),
            &mut placed::<_, P, Ij>(publish),
            |end, events, _| end.close_from(events),
        )?
    }

    fn reset<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamWriterCredential,
        code: ApplicationErrorCode,
    ) -> Result<(), ResetError<Lc>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.change_held_sending(
            held.stream_id(),
            &mut placed::<_, P, Ij>(publish),
            |end, _, _| Rs::reset(&mut end.sender, code),
        )?
    }

    fn reset_with<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamWriterCredential,
        request: Rs::ResetRequest,
    ) -> Result<(), Rs::ResetRequestError<Lc>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        let support = self.set.peer_reset_support;
        self.change_held_sending(
            held.stream_id(),
            &mut placed::<_, P, Ij>(publish),
            |end, _, _| Rs::reset_with(&mut end.sender, support, request),
        )?
    }

    /// Writes go into the send buffer at once: nothing is held back, and it
    /// is ready at once.
    fn poll_flushed(
        &mut self,
        held: &StreamWriterCredential,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), FlushError<Lc>>> {
        Poll::Ready(match self.held_sending(held.stream_id()) {
            Ok(end) => end.sender.flush(),
            Err(ended) => Err(ended.into()),
        })
    }

    fn poll_all_acknowledged(
        &mut self,
        held: &StreamWriterCredential,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), AllAcknowledgedError<Lc>>> {
        match self.held_sending(held.stream_id()) {
            Ok(end) => end.poll_all_acknowledged(cx.waker()),
            Err(ended) => Poll::Ready(Err(ended.into())),
        }
    }

    fn poll_read_into<Ij, Kp, O: BufMut + ?Sized>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamReaderCredential,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, ReadErrorOf<Lc, Rs>>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.poll_read_into_through(
            &mut placed::<_, P, Ij>(publish),
            held.stream_id(),
            cx,
            destination,
        )
    }

    fn poll_read_chunk<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamReaderCredential,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<ChunkOf>, ReadErrorOf<Lc, Rs>>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.poll_read_chunk_through(
            &mut placed::<_, P, Ij>(publish),
            held.stream_id(),
            cx,
            maximum,
        )
    }

    fn stop<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: &StreamReaderCredential,
        code: ApplicationErrorCode,
    ) -> Result<(), StopError<Lc>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.change_held_receiving(
            held.stream_id(),
            &mut placed::<_, P, Ij>(publish),
            |end, _, _| end.receiver.stop(code),
        )?
    }

    fn received_zero_rtt(&self, held: &StreamReaderCredential) -> bool {
        let id = held.stream_id();
        self.set
            .receivers
            .get(&id)
            .or_else(|| self.set.held_receivers.get(&id))
            .is_some_and(|part| part.held && part.end.receiver.received_zero_rtt())
    }

    fn supply_stream<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        urgency: Urgency,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamSummary, Idx>,
        Q: PacketPosition,
    {
        self.supply_stream_through(&mut placed::<_, P, Ij>(publish), stream_id, urgency, packet)
    }

    fn supply_reset_stream<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<ResetStreamSummary, Idx>,
        Q: PacketPosition,
    {
        let mut packet = Some(packet);
        self.change_sending(
            stream_id,
            Find::Table,
            &mut placed::<_, P, Ij>(publish),
            EventInitiator::Local,
            |end, _, publish| {
                packet
                    .take()
                    .map(|packet| end.write_reset_stream(publish, packet))
            },
        )
        .flatten()
        .or_else(|| packet.map(Supplied::Open))
        .unwrap_or_else(|| unreachable!("the packet is either written into or given back"))
    }

    fn supply_stop_sending<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StopSendingSummary, Idx>,
        Q: PacketPosition,
    {
        let mut packet = Some(packet);
        self.change_receiving(
            stream_id,
            Find::Table,
            false,
            &mut placed::<_, P, Ij>(publish),
            EventInitiator::Local,
            |end, _, publish| {
                packet
                    .take()
                    .map(|packet| end.write_stop_sending(publish, stream_id, packet))
            },
        )
        .flatten()
        .or_else(|| packet.map(Supplied::Open))
        .unwrap_or_else(|| unreachable!("the packet is either written into or given back"))
    }

    fn supply_max_data<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxDataSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut placed::<_, P, Ij>(publish);
        let supplied = self.connection_receive.write_max_data(publish, packet);
        self.connection_receive.sync_intents(publish);
        supplied
    }

    fn supply_max_stream_data<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamDataSummary, Idx>,
        Q: PacketPosition,
    {
        let mut packet = Some(packet);
        self.change_receiving(
            stream_id,
            Find::Table,
            false,
            &mut placed::<_, P, Ij>(publish),
            EventInitiator::Local,
            |end, _, publish| {
                packet
                    .take()
                    .map(|packet| end.write_max_stream_data(publish, stream_id, packet))
            },
        )
        .flatten()
        .or_else(|| packet.map(Supplied::Open))
        .unwrap_or_else(|| unreachable!("the packet is either written into or given back"))
    }

    fn supply_max_streams<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        directionality: Directionality,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<MaxStreamsSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut placed::<_, P, Ij>(publish);
        let supplied = self.set.write_max_streams(publish, directionality, packet);
        self.set.sync_intents(publish);
        supplied
    }

    fn supply_data_blocked<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<DataBlockedSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut placed::<_, P, Ij>(publish);
        let supplied = self.set.write_data_blocked(publish, packet);
        self.set.sync_intents(publish);
        supplied
    }

    fn supply_stream_data_blocked<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        stream_id: StreamId,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamDataBlockedSummary, Idx>,
        Q: PacketPosition,
    {
        let mut packet = Some(packet);
        self.change_sending(
            stream_id,
            Find::Table,
            &mut placed::<_, P, Ij>(publish),
            EventInitiator::Local,
            |end, _, publish| {
                packet
                    .take()
                    .map(|packet| end.write_stream_data_blocked(publish, packet))
            },
        )
        .flatten()
        .or_else(|| packet.map(Supplied::Open))
        .unwrap_or_else(|| unreachable!("the packet is either written into or given back"))
    }

    fn supply_streams_blocked<Ij, Kp, W, Q, Idx>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        directionality: Directionality,
        packet: OpenPacket<W, InFlightClass, Q>,
    ) -> Supplied<W, InFlightClass, Q>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<StreamsBlockedSummary, Idx>,
        Q: PacketPosition,
    {
        let publish = &mut placed::<_, P, Ij>(publish);
        let supplied = self
            .set
            .write_streams_blocked(publish, directionality, packet);
        self.set.sync_intents(publish);
        supplied
    }

    /// The acknowledgment of a STREAM frame's data and FIN, or of a reset
    /// frame, may make the sending part done; the others change nothing but
    /// the STREAM_DATA_BLOCKED signal's record.
    fn on_frame_delivered<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        summary: StreamSetFrameSummary,
    ) where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_frame_delivered_through(&mut placed::<_, P, Ij>(publish), summary);
    }

    /// What a lost frame carried is sent again as its owner has it now
    /// (RFC 9000 §13.3), as in the locked set.
    fn on_frame_lost<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        summary: StreamSetFrameSummary,
    ) where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_frame_lost_through(&mut placed::<_, P, Ij>(publish), summary);
    }

    fn on_intent_unfulfilled<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        key: StreamIntentKey,
        cause: Unfulfilled,
    ) where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        self.on_intent_unfulfilled_through(&mut placed::<_, P, Ij>(publish), key, cause);
    }
}
