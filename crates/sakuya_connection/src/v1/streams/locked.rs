//! The default stream set: the streams under one lock, each part of a
//! stream under a lock of its own ([`LockedStreamSet`]).
//!
//! One lock, the set's, holds the streams' identity ([`StreamIdLedger`]),
//! the table of the sending parts and the table of the receiving parts, the
//! queues of the streams the peer opened that the application has not
//! accepted yet, and the end of the layer. Each part of each stream is under
//! a lock of its own ([`LockedStreamEnd`]): one operation on the part has it
//! to itself. The connection's receive flow controller is under a third
//! kind of lock, as the application's reads update it too; the
//! connection's send flow controller is shared by the sending parts and
//! takes no lock.
//!
//! The set's lock and a part's lock are never held together: a part is
//! found or made under the set's lock, the set's lock is let go, and then
//! the part's lock is taken. The lock of the receive flow controller is
//! taken under a receiving part's lock, and takes none. So a frame of one
//! stream waits neither for a write on another stream nor for a read.
//!
//! The streams of a type the peer opens below one a frame names are opened
//! with it (RFC 9000 §3.2), but only the stream the frame names gets its
//! parts; each of the others gets them when its own first frame arrives,
//! and then enters the queue of streams to accept. A late frame of a stream
//! whose state was reclaimed is ignored.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use bytes::Bytes;
use sakuya_stream::{
    connection::LayerEnd,
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::{
        AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
        ConnectionSendFlowController,
    },
    receive::{StreamReceiver, composition::DefaultReceiveComposition},
    send::{StreamSender, composition::DefaultSendComposition, local_reset::LocalReset},
    send_buffer::{SendMarker, StreamSendBuffer, offset_map::OffsetMapStreamSendBuffer},
    send_options::{SendOptions, destination::AnyActiveLinkPath, urgency::Urgency},
    stream_id_ledger::{
        IdentifiedStream, InitialMaxStreams, ReceivingPartFrameType, SendingPartFrameType,
        StreamIdLedger,
    },
};
use sakuya_wire::{
    v1::{
        application_error::ApplicationErrorCode,
        encryption_level::EncryptionLevel,
        frame::{
            data_blocked::DataBlockedFrame, max_data::MaxDataFrame,
            max_stream_data::MaxStreamDataFrame, max_streams::MaxStreamsFrame,
            reset_stream::ResetStreamFrame, stop_sending::StopSendingFrame, stream::StreamFrame,
            stream_data_blocked::StreamDataBlockedFrame, streams_blocked::StreamsBlockedFrame,
        },
        role::Role,
        stream_id::{Directionality, Initiator, StreamId},
    },
    var_int::VarInt,
};
use snafu::ResultExt;

use super::{
    FlowControlParameters, ReceivingPartFrameSnafu, ResetStreamSnafu, SendingPartFrameSnafu,
    StreamSet, StreamSetFacts, StreamSetFrameError, StreamSnafu,
};

#[cfg(test)]
mod tests;

/// The sending part of a stream of the default set: the default
/// composition over [`Bytes`], with the marker `M`, sharing the
/// connection's atomic send flow controller, with the resets of RFC 9000.
type SenderOf<Lc, M> = StreamSender<
    DefaultSendComposition<Bytes, AtomicConnectionCreditReservation, M>,
    AtomicConnectionSendFlowController,
    Lc,
    LocalReset,
    Bytes,
    M,
>;

/// The receiving part of a stream of the default set: the default
/// composition, with the resets of RFC 9000.
type ReceiverOf<Lc> = StreamReceiver<DefaultReceiveComposition, Lc>;

/// The sending part of a stream as the set's table and its users share it.
type SendingPart<Lc, M> = Arc<LockedStreamEnd<SenderOf<Lc, M>>>;

/// The receiving part of a stream as the set's table and its users share
/// it.
type ReceivingPart<Lc> = Arc<LockedStreamEnd<ReceiverOf<Lc>>>;

/// What `mutex` holds, whether or not a holder panicked: a holder panics
/// only on a broken invariant of its own, and the state is taken as it was
/// left.
fn lock<X>(mutex: &Mutex<X>) -> MutexGuard<'_, X> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The default stream set: the streams under one lock, each part of a
/// stream under a lock of its own; see the [module documentation](self).
///
/// `Lc` is the type of this endpoint's reason for closing, and `M` the
/// marker each write copies onto its data, by default the send options of
/// an [`Urgency`] to [`AnyActiveLinkPath`]. It resets streams as RFC 9000
/// does, also with the `reset_stream_at` feature.
pub struct LockedStreamSet<Lc, M: SendMarker = SendOptions<Urgency, AnyActiveLinkPath>> {
    shared: Arc<StreamSetShare<Lc, M>>,
}

/// The handle of a [`LockedStreamSet`]: it shares the set's state.
pub struct LockedStreamSetHandle<Lc, M: SendMarker = SendOptions<Urgency, AnyActiveLinkPath>> {
    shared: Arc<StreamSetShare<Lc, M>>,
}

impl<Lc, M: SendMarker> Clone for LockedStreamSetHandle<Lc, M> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<Lc, M: SendMarker> fmt::Debug for LockedStreamSetHandle<Lc, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedStreamSetHandle")
            .finish_non_exhaustive()
    }
}

impl<Lc, M: SendMarker> fmt::Debug for LockedStreamSet<Lc, M> {
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

/// One part of one stream, under a lock of its own; `X` is a stream
/// sender or a stream receiver.
pub struct LockedStreamEnd<X> {
    end: Mutex<X>,
}

impl<X> LockedStreamEnd<X> {
    fn new(end: X) -> Self {
        Self {
            end: Mutex::new(end),
        }
    }

    /// The part, for one operation. Taken under no lock of the set; the
    /// lock of the connection's receive flow controller may be taken under
    /// it.
    pub fn lock(&self) -> MutexGuard<'_, X> {
        lock(&self.end)
    }
}

impl<X> fmt::Debug for LockedStreamEnd<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedStreamEnd").finish_non_exhaustive()
    }
}

/// What the set and its handles share.
struct StreamSetShare<Lc, M: SendMarker> {
    set: Mutex<SetState<Lc, M>>,
    connection_receive: Mutex<ConnectionReceiveFlowController>,
    connection_send: Arc<AtomicConnectionSendFlowController>,
    facts: StreamSetFacts,
    config: LockedStreamSetConfig,
}

/// What the set's lock holds.
struct SetState<Lc, M: SendMarker> {
    ledger: StreamIdLedger,
    senders: HashMap<StreamId, SendingPart<Lc, M>>,
    receivers: HashMap<StreamId, ReceivingPart<Lc>>,
    /// The bidirectional streams the peer opened, in the order their first
    /// frames arrived, not accepted yet.
    accept_bidirectional: VecDeque<StreamId>,
    /// The unidirectional streams the peer opened, as the bidirectional.
    accept_unidirectional: VecDeque<StreamId>,
    /// How the layer ended, once it did.
    end: Option<LayerEnd<Lc>>,
}

/// The initiator of the streams an endpoint in `role` opens.
fn initiator(role: Role) -> Initiator {
    match role {
        Role::Client => Initiator::Client,
        Role::Server => Initiator::Server,
    }
}

/// The limits of one side's transport parameters, `parameters`, on the
/// streams of each directionality the other side opens, in the ledger's
/// terms.
fn initial_max_streams(parameters: &FlowControlParameters) -> InitialMaxStreams {
    InitialMaxStreams {
        bidirectional: parameters.initial_max_streams_bidi.get(),
        unidirectional: parameters.initial_max_streams_uni.get(),
    }
}

impl StreamSetFacts {
    /// Whether this side opens `id`.
    fn opens(&self, id: StreamId) -> bool {
        id.initiator() == initiator(self.role)
    }

    /// The window of the receiving part of `id`: what this side's
    /// transport parameters grant a stream of its type (RFC 9000 §18.2).
    /// `initial_max_stream_data_bidi_local` is for the bidirectional
    /// streams this side opens, `_bidi_remote` for those the peer opens,
    /// `_uni` for the unidirectional streams the peer opens.
    fn receive_window(&self, id: StreamId) -> VarInt {
        let granted = &self.granted_to_peer;
        match (id.directionality(), self.opens(id)) {
            (Directionality::Bidirectional, true) => {
                granted.initial_max_stream_data_bidi_local.get()
            }
            (Directionality::Bidirectional, false) => {
                granted.initial_max_stream_data_bidi_remote.get()
            }
            // the peer's: a unidirectional stream of this side has no
            // receiving part
            (Directionality::Unidirectional, _) => granted.initial_max_stream_data_uni.get(),
        }
    }

    /// The limit of the sending part of `id`: what the peer's transport
    /// parameters grant a stream of its type, the side that sent them being
    /// the peer (RFC 9000 §18.2). A bidirectional stream the peer opens is
    /// its `_bidi_local`, one this side opens its `_bidi_remote`, a
    /// unidirectional stream this side opens its `_uni`.
    fn send_limit(&self, id: StreamId) -> VarInt {
        let granted = &self.granted_by_peer;
        match (id.directionality(), self.opens(id)) {
            (Directionality::Bidirectional, false) => {
                granted.initial_max_stream_data_bidi_local.get()
            }
            (Directionality::Bidirectional, true) => {
                granted.initial_max_stream_data_bidi_remote.get()
            }
            // this side's: a unidirectional stream of the peer has no
            // sending part
            (Directionality::Unidirectional, _) => granted.initial_max_stream_data_uni.get(),
        }
    }
}

impl<Lc, M: SendMarker> StreamSetShare<Lc, M> {
    /// Make the parts of `id`, a stream the peer opened that a frame just
    /// created, and queue it to be accepted. A bidirectional stream gets
    /// both parts, a unidirectional one its receiving part.
    fn create_peer_stream(&self, set: &mut SetState<Lc, M>, id: StreamId) {
        let window = self.facts.receive_window(id);
        let receiver = StreamReceiver::new(
            DefaultReceiveComposition::with_window_and_abandon_code(
                window,
                self.config.receive_abandon_code,
            ),
            window,
        );
        set.receivers
            .insert(id, Arc::new(LockedStreamEnd::new(receiver)));
        match id.directionality() {
            Directionality::Bidirectional => {
                let sender = StreamSender::new(
                    id,
                    self.facts.send_limit(id),
                    DefaultSendComposition::with_reset_codes(
                        self.config.send_abandon_code,
                        self.config.destination_exhausted_code,
                    ),
                    Arc::clone(&self.connection_send),
                );
                set.senders
                    .insert(id, Arc::new(LockedStreamEnd::new(sender)));
                set.accept_bidirectional.push_back(id);
            }
            Directionality::Unidirectional => set.accept_unidirectional.push_back(id),
        }
    }

    /// The receiving part of `id` for a frame of `frame_type`, once the
    /// frame passed the checks of the streams' identity: made if the frame
    /// creates the stream; `None` when the frame is to be ignored, as the
    /// stream was reclaimed or the layer ended.
    fn receiving_part(
        &self,
        id: StreamId,
        frame_type: ReceivingPartFrameType,
    ) -> Result<Option<ReceivingPart<Lc>>, StreamSetFrameError> {
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
    fn sending_part(
        &self,
        id: StreamId,
        frame_type: SendingPartFrameType,
    ) -> Result<Option<SendingPart<Lc, M>>, StreamSetFrameError> {
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
}

/// `M` is a marker the default send buffer takes: the send options of a
/// [`SendUrgency`](sakuya_stream::send_options::urgency::SendUrgency) to a
/// [`StreamSendDestination`](sakuya_stream::send_options::destination::StreamSendDestination).
impl<Lc, M: SendMarker> StreamSet<Lc> for LockedStreamSet<Lc, M>
where
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, M>:
        StreamSendBuffer<Bytes, AtomicConnectionCreditReservation, M>,
{
    type Handle = LockedStreamSetHandle<Lc, M>;
    type Config = LockedStreamSetConfig;

    fn new(facts: StreamSetFacts, config: LockedStreamSetConfig) -> Self {
        let ledger = StreamIdLedger::new(
            facts.role,
            initial_max_streams(&facts.granted_by_peer),
            initial_max_streams(&facts.granted_to_peer),
        );
        let set = SetState {
            ledger,
            senders: HashMap::new(),
            receivers: HashMap::new(),
            accept_bidirectional: VecDeque::new(),
            accept_unidirectional: VecDeque::new(),
            end: None,
        };
        Self {
            shared: Arc::new(StreamSetShare {
                set: Mutex::new(set),
                connection_receive: Mutex::new(ConnectionReceiveFlowController::new(
                    facts.granted_to_peer.initial_max_data.get(),
                )),
                connection_send: Arc::new(AtomicConnectionSendFlowController::new(
                    facts.granted_by_peer.initial_max_data.get(),
                )),
                facts,
                config,
            }),
        }
    }

    fn handle(&self) -> LockedStreamSetHandle<Lc, M> {
        LockedStreamSetHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// A STREAM frame in a 0-RTT packet marks its stream
    /// ([`StreamReceiver::received_zero_rtt`]) once the stream took it.
    fn on_stream_frame(
        &mut self,
        level: EncryptionLevel,
        frame: StreamFrame<Bytes>,
    ) -> Result<(), StreamSetFrameError> {
        let id = frame.stream_id().get();
        let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::Stream)?
        else {
            return Ok(());
        };
        let mut receiver = part.lock();
        let mut connection = lock(&self.shared.connection_receive);
        receiver
            .on_stream_frame(frame, &mut connection)
            .context(StreamSnafu)?;
        if level == EncryptionLevel::ZeroRtt {
            receiver.mark_received_zero_rtt();
        }
        Ok(())
    }

    fn on_reset_stream(&mut self, frame: ResetStreamFrame) -> Result<(), StreamSetFrameError> {
        let id = frame.stream_id().get();
        let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::ResetStream)?
        else {
            return Ok(());
        };
        let mut receiver = part.lock();
        let mut connection = lock(&self.shared.connection_receive);
        receiver
            .on_reset_stream(frame, &mut connection)
            .context(ResetStreamSnafu)
    }

    fn on_stop_sending(&mut self, frame: StopSendingFrame) -> Result<(), StreamSetFrameError> {
        let id = frame.stream_id().get();
        if let Some(part) = self
            .shared
            .sending_part(id, SendingPartFrameType::StopSending)?
        {
            part.lock()
                .on_stop_sending(frame.application_error_code().get());
        }
        Ok(())
    }

    fn on_max_data(&mut self, frame: MaxDataFrame) -> Result<(), StreamSetFrameError> {
        self.shared
            .connection_send
            .on_max_data(frame.maximum_data().get());
        Ok(())
    }

    fn on_max_stream_data(&mut self, frame: MaxStreamDataFrame) -> Result<(), StreamSetFrameError> {
        let id = frame.stream_id().get();
        if let Some(part) = self
            .shared
            .sending_part(id, SendingPartFrameType::MaxStreamData)?
        {
            part.lock()
                .on_max_stream_data(frame.maximum_stream_data().get());
        }
        Ok(())
    }

    /// A limit that does not grow is ignored (RFC 9000 §19.11).
    fn on_max_streams(&mut self, frame: MaxStreamsFrame) -> Result<(), StreamSetFrameError> {
        let mut set = lock(&self.shared.set);
        if set.end.is_none() {
            set.ledger
                .on_max_streams(frame.directionality(), frame.maximum_streams().get());
        }
        Ok(())
    }

    /// The default policies send nothing for it; it changes nothing.
    fn on_data_blocked(&mut self, _: DataBlockedFrame) -> Result<(), StreamSetFrameError> {
        Ok(())
    }

    fn on_stream_data_blocked(
        &mut self,
        frame: StreamDataBlockedFrame,
    ) -> Result<(), StreamSetFrameError> {
        let id = frame.stream_id().get();
        if let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::StreamDataBlocked)?
        {
            part.lock()
                .on_stream_data_blocked(frame.maximum_stream_data().get());
        }
        Ok(())
    }

    /// The default policies send nothing for it; it changes nothing. A
    /// limit beyond 2^60 is refused when the frame is read (RFC 9000
    /// §19.14).
    fn on_streams_blocked(&mut self, _: StreamsBlockedFrame) -> Result<(), StreamSetFrameError> {
        Ok(())
    }

    /// The end is kept first, under the set's lock; each part hears of it
    /// afterwards, under its own lock. Only the first end is kept.
    fn layer_ended(&mut self, end: LayerEnd<Lc>) {
        let (senders, receivers) = {
            let mut set = lock(&self.shared.set);
            if set.end.is_some() {
                return;
            }
            set.end = Some(end.clone());
            (
                set.senders.values().cloned().collect::<Vec<_>>(),
                set.receivers.values().cloned().collect::<Vec<_>>(),
            )
        };
        for sender in senders {
            sender.lock().on_layer_ended(end.clone());
        }
        for receiver in receivers {
            receiver.lock().layer_ended(end.clone());
        }
    }
}
