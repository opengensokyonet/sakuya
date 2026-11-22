//! The application's side of [`LockedStreamSet`](super::LockedStreamSet):
//! the shares of a stream's parts its writers and readers hold apart from
//! the connection ([`LockedStreamSendShare`], [`LockedStreamReceiveShare`]),
//! what an operation on a part reaches, and opening and accepting streams
//! with shares on the handle of its established layer.
//!
//! A share holds the part of the stream it is of and the set's shared
//! state, where the handle of the strategy's intake the set publishes
//! through is; for an operation of a capability through the shared
//! connection ([`SharedStreamSend`], [`SharedStreamReceive`]), the set
//! finds the two itself, the part by the stream's ID
//! ([`StreamSet::poll_write`] and the others).
//!
//! [`SharedStreamSend`]: crate::v1::application_handles::shared_stream::SharedStreamSend
//! [`SharedStreamReceive`]: crate::v1::application_handles::shared_stream::SharedStreamReceive
//! Both reach the part the same way (`SendingAccess`, `ReceivingAccess`),
//! and every operation is written once for both.
//! Every operation changes the part under its
//! lock and then brings the part's intents to what is due, as the driver's
//! side does; what waits keeps its waker under the same lock. The order of
//! the locks is in the [parent module's documentation](super).
//!
//! - A write that finds no room in the stream's limit waits for the peer's
//!   MAX_STREAM_DATA; one that finds no connection credit has DATA_BLOCKED
//!   sent and waits for MAX_DATA or for credit another stream gives back.
//! - A read updates the stream's and the connection's released data, and
//!   so their MAX_STREAM_DATA and MAX_DATA; without data it waits for a
//!   STREAM or RESET_STREAM frame of the stream.
//! - Opening waits while the peer's limit allows no stream, and has
//!   STREAMS_BLOCKED sent (RFC 9000 §4.6); accepting waits for the first
//!   frame of a stream of the peer.
//! - Everything waiting ends when the layer does, and when the driver
//!   panicked: every operation first looks whether the driver's panic
//!   marked the layer's end, under the lock it keeps its waker under, and
//!   then reports that end without changing the part, the set or the
//!   intents.
//!
//! Once the last holder of a credential drops its share or capability, the
//! part is given up: the writer's tells the sending part its writer was
//! abandoned, the reader's that its reader was dropped; the parts'
//! termination policies decide what follows. A part held through the
//! shared connection is then no longer held, and may be reclaimed. Once the
//! driver panicked, dropping changes nothing.
//!
//! The events of the streams ([`SharedEvents`]) are given here as on the
//! driver's side: every operation, and dropping a share, gives the change of
//! its part's state as this side's, under the part's lock. A write gives
//! the data it took, a close the end of the stream, and a read the data it
//! gave the application and, the first time, the peer's reset, as moves
//! between the application and the transport; opening a stream gives its
//! parts as made by this side.
//!
//! An operation, or dropping a share, that leaves the part done may
//! reclaim the stream, as the driver's side does (see the [parent module's
//! documentation](super)): the share keeps its part after that, and the
//! part keeps only its last result — a reader returns the same end or
//! error again, a writer reports that the stream was closed or reset.

use alloc::sync::Arc;
use core::{
    future::{Future, poll_fn, ready},
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use sakuya_stream_sets::resets::{StreamResets, StreamResetsOf, StreamResetsOfParts};

use bytes::{Buf, BufMut};
use nitori_io::{Read, ReadChunk};
use nitori_tls::role;
use sakuya_stream_v1::{
    connection::{LayerEnd, LayerEndedError},
    receive::{read::ReadOutcome, stop::StopError},
    send::{
        finish::{CloseError, ResetError},
        write::{FlushError, WriteError, WriteOutcome, WriteReport, WriteWait},
    },
    send_options::{
        NoSendOptions, SendOptions, destination::AnyActiveLinkPath, urgency::SendUrgency,
    },
};
use sakuya_wire_v1::var_int::VarInt;
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode,
    stream_id::{Directionality, StreamId},
};

use super::{
    LockedStreamEnd, LockedStreamSetHandle, ReceivingPart, SendingPart, SetStateOf, StreamSetShare,
    lock,
};
use crate::v1::streams::set_state::{
    ChunkOf, ConnectionReceive, ReadErrorOf, ReceivingEnd, SendingEnd, WriteLimitReasonOf,
    new_receiving_end, new_sending_end, read_block, read_count,
};
use crate::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    send_strategy::IntentPublisher,
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::GetAt,
    v1::{
        Choices, CloseCauseOf, SendParametersOf, StreamSetFamilyOf,
        application_handles::{
            connection::{ConnectionHandleRemainsOf, ConnectionHandleStateOf, keep_waker},
            credential::CredentialPointer,
            established_layer::{
                AcceptDetachedStreams, EstablishedLayerHandle, LayerSelection, OpenDetachedStreams,
                TryOpenStreamError,
            },
            stream::{AllAcknowledgedError, StreamRead, StreamReader, StreamWrite, StreamWriter},
        },
        events::{EventInitiator, NoEvents, SharedEvents},
        send::SendTypes,
        send_planning::{ComponentPublishing, HostSendStrategyTypes},
        streams::{
            StreamReaderCredential, StreamSet, StreamWriterCredential, StreamsOf,
            send::StreamIntent,
        },
    },
};
use sakuya_stream_v1::connection_send_credit::ConnectionSendFlowController;
use sakuya_wire::parts::Selector;

#[cfg(test)]
mod tests;

// ---- what one operation on a part reaches ----

/// What one operation on a sending part reaches (`SendingAccess`): the
/// part, the set's shared state, and a clone of the handle there that its
/// intents are published through. A share holds the first two; a
/// capability through the shared connection finds them in the layer it is
/// lent. Every operation of a writer is written here once, for both.
pub(super) struct SendingAccess<'a, Lc, K, Rs: StreamResets, P, H, E> {
    part: &'a SendingPart<Lc, K, Rs, P>,
    pub(super) shared: &'a StreamSetShare<Lc, K, H, Rs, P, E>,
    publish: H,
}

impl<Lc, K, Rs: StreamResets, P, H, E> SendingAccess<'_, Lc, K, Rs, P, H, E>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    /// What [`with_part`](Self::with_part) does under the part's lock: the
    /// change, the intents and the mark of whether the part is done; the
    /// stream's ID with what `change` came to.
    fn change_part<R>(
        &mut self,
        change: impl FnOnce(&mut SendingEnd<Lc, K, Rs, P>) -> R,
    ) -> Result<(R, StreamId), LayerEndedError<Lc>> {
        let mut end = self.part.lock();
        if let Some(marked) = self.shared.panic_end() {
            return Err(LayerEndedError::new(marked.clone()));
        }
        let before = self.shared.state_before(&*end);
        let result = change(&mut end);
        end.sync_intents(&mut self.publish);
        self.part.note_done(&end);
        let id = end.sender.stream_id();
        self.shared
            .state_after(id, before, &*end, EventInitiator::Local);
        Ok((result, id))
    }

    /// Change the part with `change` under its lock, and bring its intents
    /// to what is due then; with the lock let go, reclaim the stream if it
    /// is done (`StreamSetShare::reclaim_if_done`). Once the driver
    /// panicked, the end it marked, and nothing changes.
    pub(super) fn with_part<R>(
        &mut self,
        change: impl FnOnce(&mut SendingEnd<Lc, K, Rs, P>) -> R,
    ) -> Result<R, LayerEndedError<Lc>> {
        let (result, id) = self.change_part(change)?;
        self.shared
            .reclaim_if_done(self.part, id, &mut self.publish);
        Ok(result)
    }

    /// The writer gives the stream up: the sending part hears that its
    /// writer was abandoned, the part is no longer held, and the stream is
    /// reclaimed if it is done. Once the driver panicked, nothing changes.
    pub(super) fn give_up(&mut self) {
        let Ok(((), id)) = self.change_part(SendingEnd::give_up) else {
            return;
        };
        self.part.let_go();
        self.shared
            .reclaim_if_done(self.part, id, &mut self.publish);
    }

    /// See [`StreamWrite::poll_write_with`] and the
    /// [module documentation](self).
    #[allow(clippy::type_complexity)] // the write's result
    pub(super) fn poll_write_with<B: Buf + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &P,
        destination: &AnyActiveLinkPath,
    ) -> Poll<Result<WriteReport, WriteError<WriteLimitReasonOf<Rs, P>, Lc>>> {
        let marker = SendOptions::new(parameters.clone(), *destination);
        let shared = self.shared;
        loop {
            let outcome =
                self.with_part(|end| end.write_from(&shared.events, input, &marker, cx.waker()));
            let outcome = match outcome {
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
            // in between wakes it; the part's lock is let go before the
            // set's is taken
            let connection = &self.shared.connection_send;
            connection.register_credit_waker(cx.waker());
            // the strategy's intake is not used once the driver panicked;
            // a panic marked after this wakes the writer's waker
            if let Some(marked) = self.shared.panic_end() {
                return Poll::Ready(Err(LayerEndedError::new(marked.clone()).into()));
            }
            let limit = connection.limit();
            self.shared.with_set(&mut self.publish, |set, _| {
                set.connection.data_blocked_signal.on_write_blocked(limit);
            });
            if connection.available() == VarInt::ZERO {
                return Poll::Pending;
            }
        }
    }

    /// See [`StreamWrite::close`]: the end moves to the transport when the
    /// close ends a stream that was open; closing again moves nothing.
    pub(super) fn close(&mut self) -> Result<(), CloseError<Lc>> {
        let shared = self.shared;
        self.with_part(|end| end.close_from(&shared.events))?
    }

    /// See [`StreamWrite::reset`].
    pub(super) fn reset(&mut self, code: ApplicationErrorCode) -> Result<(), ResetError<Lc>> {
        self.with_part(|end| Rs::reset(&mut end.sender, code))?
    }

    /// See [`LockedStreamSendShare::reset_with`].
    pub(super) fn reset_with(
        &mut self,
        request: Rs::ResetRequest,
    ) -> Result<(), Rs::ResetRequestError<Lc>> {
        let support = self.shared.peer_reset_support();
        self.with_part(|end| Rs::reset_with(&mut end.sender, support, request))?
    }

    /// See [`StreamWrite::flush`]: writes go into the send buffer at once,
    /// so nothing is held back.
    pub(super) fn flush(&mut self) -> Result<(), FlushError<Lc>> {
        let end = self.part.lock();
        match self.shared.panic_end() {
            Some(marked) => Err(LayerEndedError::new(marked.clone()).into()),
            None => end.sender.flush(),
        }
    }

    /// One poll of [`StreamWrite::all_acknowledged`].
    pub(super) fn poll_all_acknowledged(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), AllAcknowledgedError<Lc>>> {
        let mut end = self.part.lock();
        if let Some(marked) = self.shared.panic_end() {
            return Poll::Ready(Err(LayerEndedError::new(marked.clone()).into()));
        }
        end.poll_all_acknowledged(cx.waker())
    }
}

/// What one operation on a receiving part reaches (`ReceivingAccess`), as
/// [`SendingAccess`] is for a sending part, with the stream's ID.
pub(super) struct ReceivingAccess<'a, Lc, K, Rs: StreamResets, P, H, E> {
    part: &'a ReceivingPart<Lc, K, Rs, P>,
    stream_id: StreamId,
    shared: &'a StreamSetShare<Lc, K, H, Rs, P, E>,
    publish: H,
}

impl<Lc, K, Rs: StreamResets, P, H, E> ReceivingAccess<'_, Lc, K, Rs, P, H, E>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    /// Change the part with `change` under its lock; then, with the receive
    /// flow controller's lock taken under it, report what the stream
    /// released, and bring the intents of the connection's receiving and of
    /// the part to what is due. With both locks let go, reclaim the stream
    /// if it is done (`StreamSetShare::reclaim_if_done`). Once the driver
    /// panicked, the end it marked, and nothing changes.
    fn with_part<R>(
        &mut self,
        change: impl FnOnce(&mut ReceivingEnd<Lc, K, Rs, P>) -> R,
    ) -> Result<R, LayerEndedError<Lc>> {
        let result = self.change_part(change)?;
        self.shared
            .reclaim_if_done(self.part, self.stream_id, &mut self.publish);
        Ok(result)
    }

    /// What [`with_part`](Self::with_part) does under the part's lock: the
    /// change, the report of what was released, the intents, and the mark
    /// of whether the part is done.
    fn change_part<R>(
        &mut self,
        change: impl FnOnce(&mut ReceivingEnd<Lc, K, Rs, P>) -> R,
    ) -> Result<R, LayerEndedError<Lc>> {
        let mut end = self.part.lock();
        if let Some(marked) = self.shared.panic_end() {
            return Err(LayerEndedError::new(marked.clone()));
        }
        let before = self.shared.state_before(&*end);
        let result = change(&mut end);
        {
            let mut connection = lock(&self.shared.connection_receive);
            let ConnectionReceive { flow, .. } = &mut *connection;
            let released = end.receiver.report_release(flow);
            // invariant: every stream of the set accounts its data with the
            // set's one controller
            debug_assert!(
                released.is_ok(),
                "a stream releases what it accounted: {released:?}"
            );
            connection.sync_intents(&mut self.publish);
        }
        end.sync_intents(self.stream_id, &mut self.publish);
        self.part.note_done(&end);
        self.shared
            .state_after(self.stream_id, before, &*end, EventInitiator::Local);
        Ok(result)
    }

    /// The reader gives the reading up: the receiving part hears that its
    /// reader was dropped, the part is no longer held, and the stream is
    /// reclaimed if it is done. Once the driver panicked, nothing changes.
    pub(super) fn give_up(&mut self) {
        if self.change_part(ReceivingEnd::give_up).is_err() {
            return;
        }
        self.part.let_go();
        self.shared
            .reclaim_if_done(self.part, self.stream_id, &mut self.publish);
    }

    /// Read with `read`, which gives what the receiving part gives; keep
    /// the waker of `cx` when it has to wait
    /// ([`ReceivingEnd::poll_read_with`]).
    fn poll_read_with<R>(
        &mut self,
        cx: &mut Context<'_>,
        read: impl FnOnce(
            &mut ReceivingEnd<Lc, K, Rs, P>,
        ) -> Result<ReadOutcome<R>, ReadErrorOf<Lc, Rs>>,
    ) -> Poll<Result<ReadOutcome<R>, ReadErrorOf<Lc, Rs>>> {
        let (shared, stream_id) = (self.shared, self.stream_id);
        self.with_part(|end| end.poll_read_with(stream_id, &shared.events, cx.waker(), read))
            .unwrap_or_else(|ended| Poll::Ready(Err(ended.into())))
    }

    /// Read into `destination`; `Ok(0)` at the end of the stream or for no
    /// room, as nitori_io's `Read` has it.
    pub(in crate::v1::streams) fn poll_read_into<O: BufMut + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, ReadErrorOf<Lc, Rs>>> {
        read_count(self.poll_read_with(cx, |end| end.receiver.read_into(destination)))
    }

    /// Read a block of at most `maximum` bytes; `None` at the end of the
    /// stream.
    pub(in crate::v1::streams) fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<ChunkOf>, ReadErrorOf<Lc, Rs>>> {
        read_block(self.poll_read_with(cx, |end| end.receiver.read_chunk(maximum)))
    }

    /// See [`StreamRead::stop`].
    pub(super) fn stop(&mut self, code: ApplicationErrorCode) -> Result<(), StopError<Lc>> {
        self.with_part(|end| end.receiver.stop(code))?
    }

    /// Whether a STREAM frame of the stream arrived in a 0-RTT packet and
    /// was taken.
    pub(super) fn received_zero_rtt(&self) -> bool {
        self.part.lock().receiver.received_zero_rtt()
    }
}

impl<Lc, K, H: Clone, Rs: StreamResets, P, E> StreamSetShare<Lc, K, H, Rs, P, E> {
    /// What an operation on the sending part `part` reaches, publishing
    /// through a clone of the set's intake.
    pub(super) fn sending_access<'a>(
        &'a self,
        part: &'a SendingPart<Lc, K, Rs, P>,
    ) -> SendingAccess<'a, Lc, K, Rs, P, H, E> {
        SendingAccess {
            part,
            shared: self,
            publish: self.intake.clone(),
        }
    }

    /// What an operation on the receiving part `part` of `stream_id`
    /// reaches, publishing through a clone of the set's intake.
    pub(super) fn receiving_access<'a>(
        &'a self,
        part: &'a ReceivingPart<Lc, K, Rs, P>,
        stream_id: StreamId,
    ) -> ReceivingAccess<'a, Lc, K, Rs, P, H, E> {
        ReceivingAccess {
            part,
            stream_id,
            shared: self,
            publish: self.intake.clone(),
        }
    }
}

// ---- the shares ----

/// This side's share of a stream's sending part in a [`LockedStreamSet`]
/// (`LockedStreamSendShare`), which a [`StreamWriter`] holds apart from the
/// connection: the part, the set's shared state, with the handle `H` of the
/// strategy's intake its intents are published through, and the pointer `C`
/// to the credential of the writer ([`CredentialPointer`]).
///
/// It can be cloned where `C` can: opened or accepted with the credential
/// itself, it is turned into one with a shared credential by
/// [`into_shared`](Self::into_shared). Once the last holder of the
/// credential drops its share, the writer gives the stream up.
///
/// [`LockedStreamSet`]: super::LockedStreamSet
pub struct LockedStreamSendShare<
    Lc,
    K,
    Rs: StreamResets,
    P,
    H,
    E = NoEvents,
    C = StreamWriterCredential,
> where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamWriterCredential>,
{
    part: SendingPart<Lc, K, Rs, P>,
    pub(super) shared: Arc<StreamSetShare<Lc, K, H, Rs, P, E>>,
    /// `None` only once it was handed back or moved on.
    credential: Option<C>,
}

/// This side's share of a stream's receiving part in a [`LockedStreamSet`]
/// (`LockedStreamReceiveShare`), which a [`StreamReader`] holds, as
/// [`LockedStreamSendShare`] is of a sending part.
///
/// `Ro` is the role of this side, [`role::Client`] or [`role::Server`]: a
/// server's reader also tells whether the stream had data in 0-RTT
/// packets ([`StreamReader::received_zero_rtt`]).
///
/// [`LockedStreamSet`]: super::LockedStreamSet
pub struct LockedStreamReceiveShare<
    Lc,
    K,
    Rs: StreamResets,
    P,
    H,
    Ro,
    E = NoEvents,
    C = StreamReaderCredential,
> where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential>,
{
    part: ReceivingPart<Lc, K, Rs, P>,
    stream_id: StreamId,
    shared: Arc<StreamSetShare<Lc, K, H, Rs, P, E>>,
    credential: Option<C>,
    role: PhantomData<fn() -> Ro>,
}

/// Nothing of a share is pinned.
impl<Lc, K, Rs: StreamResets, P, H, E, C> Unpin for LockedStreamSendShare<Lc, K, Rs, P, H, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamWriterCredential>,
{
}

/// Nothing of a share is pinned.
impl<Lc, K, Rs: StreamResets, P, H, Ro, E, C> Unpin
    for LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential>,
{
}

/// A clone holds the same credential, and is a writer of the same stream.
impl<Lc, K, Rs: StreamResets, P, H, E, C> Clone for LockedStreamSendShare<Lc, K, Rs, P, H, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamWriterCredential> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            part: Arc::clone(&self.part),
            shared: Arc::clone(&self.shared),
            credential: self.credential.clone(),
        }
    }
}

/// A clone holds the same credential, and is a reader of the same stream.
impl<Lc, K, Rs: StreamResets, P, H, Ro, E, C> Clone
    for LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential> + Clone,
{
    fn clone(&self) -> Self {
        Self {
            part: Arc::clone(&self.part),
            stream_id: self.stream_id,
            shared: Arc::clone(&self.shared),
            credential: self.credential.clone(),
            role: PhantomData,
        }
    }
}

impl<Lc, K, Rs: StreamResets, P, H, E, C> core::fmt::Debug
    for LockedStreamSendShare<Lc, K, Rs, P, H, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamWriterCredential>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockedStreamSendShare")
            .finish_non_exhaustive()
    }
}

impl<Lc, K, Rs: StreamResets, P, H, Ro, E, C> core::fmt::Debug
    for LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockedStreamReceiveShare")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl<Lc, K, Rs: StreamResets, P, H, E, C> LockedStreamSendShare<Lc, K, Rs, P, H, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamWriterCredential>,
{
    /// What its operations reach.
    pub(super) fn access(&self) -> SendingAccess<'_, Lc, K, Rs, P, H, E> {
        self.shared.sending_access(&self.part)
    }

    /// Resets the stream as `request` asks, a request of the reset kind
    /// ([`StreamResets::ResetRequest`]), with what the peer's parameters
    /// allow: those of this handshake once they are known. A part that
    /// adds the request gives the writer its capability through this.
    ///
    /// # Errors
    ///
    /// As [`StreamResets::reset_with`], and the end the driver marked once
    /// it panicked; nothing changes then.
    pub fn reset_with(
        &mut self,
        request: Rs::ResetRequest,
    ) -> Result<(), Rs::ResetRequestError<Lc>> {
        self.access().reset_with(request)
    }
}

impl<Lc, K, Rs: StreamResets, P, H, E> LockedStreamSendShare<Lc, K, Rs, P, H, E>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    /// The same share with the credential behind the shared pointer `Q`
    /// ([`Arc`] or [`Rc`](alloc::rc::Rc)), so that it can be cloned.
    pub fn into_shared<Q>(mut self) -> LockedStreamSendShare<Lc, K, Rs, P, H, E, Q>
    where
        Q: CredentialPointer<StreamWriterCredential> + From<StreamWriterCredential>,
    {
        LockedStreamSendShare {
            part: Arc::clone(&self.part),
            shared: Arc::clone(&self.shared),
            credential: self.credential.take().map(Q::from),
        }
    }
}

/// A writer with an independent share turns into one with a shared
/// credential, which can be cloned.
impl<Lc, K, Rs: StreamResets, P, H, E, O> StreamWriter<LockedStreamSendShare<Lc, K, Rs, P, H, E>, O>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    /// The same writer with the credential behind the shared pointer `Q`
    /// ([`LockedStreamSendShare::into_shared`]).
    #[allow(clippy::type_complexity)] // a writer of eight type parameters
    pub fn into_shared<Q>(self) -> StreamWriter<LockedStreamSendShare<Lc, K, Rs, P, H, E, Q>, O>
    where
        Q: CredentialPointer<StreamWriterCredential> + From<StreamWriterCredential>,
    {
        self.map_share(LockedStreamSendShare::into_shared)
    }
}

/// A reader with an independent share turns into one with a shared
/// credential, which can be cloned.
impl<Lc, K, Rs: StreamResets, P, H, Ro, E>
    StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E>>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    /// The same reader with the credential behind the shared pointer `Q`
    /// ([`LockedStreamReceiveShare::into_shared`]).
    #[allow(clippy::type_complexity)] // a reader of eight type parameters
    pub fn into_shared<Q>(self) -> StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, Q>>
    where
        Q: CredentialPointer<StreamReaderCredential> + From<StreamReaderCredential>,
    {
        StreamReader::new(self.share.into_shared())
    }
}

/// The last holder of the credential gives the stream up when it drops its
/// share.
impl<Lc, K, Rs: StreamResets, P, H, E, C> Drop for LockedStreamSendShare<Lc, K, Rs, P, H, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamWriterCredential>,
{
    /// Once the driver panicked, nothing is given up: the part is not
    /// changed any more.
    fn drop(&mut self) {
        if self
            .credential
            .take()
            .and_then(C::into_credential)
            .is_some()
        {
            self.access().give_up();
        }
    }
}

/// The sending part's operations, under its lock; see the
/// [module documentation](self).
impl<Lc, K, Rs: StreamResets, P, H, E, C> StreamWrite
    for LockedStreamSendShare<Lc, K, Rs, P, H, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamWriterCredential>,
{
    type Parameters = P;
    type Destination = AnyActiveLinkPath;
    type CloseCause = Lc;
    type WriteLimitReason = WriteLimitReasonOf<Rs, P>;

    fn poll_write_with<B: Buf + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        input: &mut B,
        parameters: &P,
        destination: &AnyActiveLinkPath,
    ) -> Poll<Result<WriteReport, WriteError<WriteLimitReasonOf<Rs, P>, Lc>>> {
        self.access()
            .poll_write_with(cx, input, parameters, destination)
    }

    /// The end moves to the transport when the close ends a stream that
    /// was open; closing again moves nothing.
    fn close(&mut self) -> Result<(), CloseError<Lc>> {
        self.access().close()
    }

    fn reset(&mut self, code: ApplicationErrorCode) -> Result<(), ResetError<Lc>> {
        self.access().reset(code)
    }

    /// Writes go into the send buffer at once: nothing is held back, and it
    /// is done at once.
    fn flush(&mut self) -> impl Future<Output = Result<(), FlushError<Lc>>> {
        ready(self.access().flush())
    }

    fn all_acknowledged(&mut self) -> impl Future<Output = Result<(), AllAcknowledgedError<Lc>>> {
        poll_fn(|cx| self.access().poll_all_acknowledged(cx))
    }
}

impl<Lc, K, Rs: StreamResets, P, H, Ro, E, C> LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential>,
{
    /// What its operations reach.
    fn access(&self) -> ReceivingAccess<'_, Lc, K, Rs, P, H, E> {
        self.shared.receiving_access(&self.part, self.stream_id)
    }
}

impl<Lc, K, Rs: StreamResets, P, H, Ro, E> LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    /// The same share with the credential behind the shared pointer `Q`
    /// ([`Arc`] or [`Rc`](alloc::rc::Rc)), so that it can be cloned.
    pub fn into_shared<Q>(mut self) -> LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, Q>
    where
        Q: CredentialPointer<StreamReaderCredential> + From<StreamReaderCredential>,
    {
        LockedStreamReceiveShare {
            part: Arc::clone(&self.part),
            stream_id: self.stream_id,
            shared: Arc::clone(&self.shared),
            credential: self.credential.take().map(Q::from),
            role: PhantomData,
        }
    }
}

/// The last holder of the credential gives the reading up when it drops
/// its share.
impl<Lc, K, Rs: StreamResets, P, H, Ro, E, C> Drop
    for LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential>,
{
    /// Once the driver panicked, nothing is given up: the part is not
    /// changed any more.
    fn drop(&mut self) {
        if self
            .credential
            .take()
            .and_then(C::into_credential)
            .is_some()
        {
            self.access().give_up();
        }
    }
}

/// The receiving part's STOP, under its lock.
impl<Lc, K, Rs: StreamResets, P, H, Ro, E, C> StreamRead
    for LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential>,
{
    type CloseCause = Lc;

    fn stop(&mut self, code: ApplicationErrorCode) -> Result<(), StopError<Lc>> {
        self.access().stop(code)
    }
}

/// A reader of the locked set reads its receiving part.
impl<Lc, K, Rs: StreamResets, P, H, Ro, E, C> Read
    for StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, C>>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential>,
{
    type Error = ReadErrorOf<Lc, Rs>;

    fn poll_read<'visit, Output: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        destination: &mut Output,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        host.get_pin_mut()
            .get_mut()
            .share
            .access()
            .poll_read_into(cx, destination)
    }
}

/// A reader of the locked set reads blocks of its receiving part, cut at
/// the maximum.
impl<Lc, K, Rs: StreamResets, P, H, Ro, E, C> ReadChunk
    for StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E, C>>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential>,
{
    type Chunk = ChunkOf;

    fn poll_read_chunk<'visit>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<ChunkOf>, Self::Error>>
    where
        Self: 'visit,
    {
        host.get_pin_mut()
            .get_mut()
            .share
            .access()
            .poll_read_chunk(cx, maximum)
    }
}

/// A server's reader tells whether the stream had data in 0-RTT packets,
/// which may be replayed (RFC 9001 §9.2); a client receives none
/// (RFC 9001 §5.6), and its reader has no such method:
///
/// ```compile_fail,E0599
/// # use sakuya_connection::v1::{
/// #     application_handles::stream::StreamReader,
/// #     streams::locked::application::LockedStreamReceiveShare,
/// # };
/// # use nitori_tls::role::Client;
/// fn ask<Lc, K, Rs, P, H>(
///     reader: &StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H, Client>>,
/// ) -> bool
/// where
///     Rs: sakuya_stream_sets::resets::StreamResets,
///     P: Clone + PartialEq + Default + sakuya_stream_v1::send_options::urgency::SendUrgency,
///     H: sakuya_connection::send_strategy::IntentPublisher<
///             sakuya_connection::v1::streams::send::StreamIntent<P>,
///             sakuya_connection::send_strategy::AnyActiveLinkPath,
///             Ticket = K,
///         > + Clone,
/// {
///     reader.received_zero_rtt()
/// }
/// ```
impl<Lc, K, Rs: StreamResets, P, H, E, C>
    StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H, role::Server, E, C>>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer<StreamReaderCredential>,
{
    /// Whether a STREAM frame of the stream arrived in a 0-RTT packet and
    /// was taken: data the client sent in 0-RTT, which an attacker may
    /// replay (RFC 9001 §9.2). It is marked by the packet's encryption
    /// level, whenever the frame arrives, and stays once marked; data the
    /// client sent again in 1-RTT packets is not marked. A server that
    /// takes no 0-RTT data receives none there, so it is `false` for every
    /// stream.
    pub fn received_zero_rtt(&self) -> bool {
        self.share.access().received_zero_rtt()
    }
}

// ---- opening and accepting ----

/// The parts of a stream as opening or accepting finds them: the sending
/// part, unless the peer opened it unidirectional; the receiving part,
/// unless this side opened it unidirectional.
type FoundParts<Lc, K, Rs, P> = (
    Option<SendingPart<Lc, K, Rs, P>>,
    Option<ReceivingPart<Lc, K, Rs, P>>,
);

/// A stream opening or accepting finds, with its parts.
type FoundStream<Lc, K, Rs, P> = (StreamId, FoundParts<Lc, K, Rs, P>);

/// Why a stream could not be opened now.
pub(super) enum OpenRefused<Lc> {
    /// The peer's limit allows no more streams of the type.
    AtLimit,
    /// The layer ended.
    Ended(LayerEnd<Lc>),
}

impl<Lc, K, H, Rs: StreamResets, P, E> StreamSetShare<Lc, K, H, Rs, P, E>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K>,
    E: SharedEvents,
{
    /// Make the parts of `id`, a stream this side opens: a bidirectional
    /// one gets both, a unidirectional one its sending part; each is held
    /// through the shared connection if `held` says so. Each part made is
    /// an event of this side's.
    fn create_local_stream(
        &self,
        set: &mut SetStateOf<Lc, K, Rs, P>,
        id: StreamId,
        held: bool,
    ) -> FoundParts<Lc, K, Rs, P> {
        let sending = new_sending_end(
            &self.facts,
            &set.granted_by_peer,
            id,
            self.config.send_abandon_code,
            self.config.destination_exhausted_code,
            &self.connection_send,
        );
        self.part_made(id, &sending, EventInitiator::Local);
        let sending = Arc::new(LockedStreamEnd::new(sending));
        if held {
            sending.hold();
        }
        set.senders.insert(id, Arc::clone(&sending));
        let receiving = (id.directionality() == Directionality::Bidirectional).then(|| {
            let receiving = new_receiving_end(&self.facts, id, self.config.receive_abandon_code);
            self.part_made(id, &receiving, EventInitiator::Local);
            let receiving = Arc::new(LockedStreamEnd::new(receiving));
            if held {
                receiving.hold();
            }
            set.receivers.insert(id, Arc::clone(&receiving));
            receiving
        });
        (Some(sending), receiving)
    }

    /// Open the next stream of `directionality` of this side under the
    /// set's lock, its parts held through the shared connection if `held`
    /// says so; at the limit, keep `waker` if one is given and have
    /// STREAMS_BLOCKED sent, published through `publish`.
    pub(super) fn open_local(
        &self,
        directionality: Directionality,
        publish: &mut H,
        waker: Option<&Waker>,
        held: bool,
    ) -> Result<FoundStream<Lc, K, Rs, P>, OpenRefused<Lc>> {
        let mut set = lock(&self.set);
        // once the driver panicked, the set is not changed any more
        if let Some(end) = self.panic_end().or(set.end.as_ref()) {
            return Err(OpenRefused::Ended(end.clone()));
        }
        let opened = match set.ledger.open_local(directionality) {
            Ok(id) => Ok((id, self.create_local_stream(&mut set, id, held))),
            Err(_) => {
                if let Some(waker) = waker {
                    keep_waker(set.open_wakers.get_mut(directionality), waker);
                }
                Err(OpenRefused::AtLimit)
            }
        };
        set.sync_intents(publish);
        opened
    }

    /// The next stream of `directionality` the peer opened, under the
    /// set's lock, its parts held through the shared connection from then
    /// on if `held` says so; `Pending` with the waker of `cx` kept while
    /// none is there.
    #[allow(clippy::type_complexity)] // a stream of four type parameters
    pub(super) fn poll_accept(
        &self,
        cx: &mut Context<'_>,
        directionality: Directionality,
        held: bool,
    ) -> Poll<Result<FoundStream<Lc, K, Rs, P>, LayerEnd<Lc>>> {
        let mut set = lock(&self.set);
        if let Some(end) = self.panic_end().or(set.end.as_ref()) {
            return Poll::Ready(Err(end.clone()));
        }
        loop {
            let queue = match directionality {
                Directionality::Bidirectional => &mut set.accept_bidirectional,
                Directionality::Unidirectional => &mut set.accept_unidirectional,
            };
            let Some(id) = queue.pop_front() else {
                keep_waker(set.accept_wakers.get_mut(directionality), cx.waker());
                return Poll::Pending;
            };
            let parts = (
                set.senders.get(&id).cloned(),
                set.receivers.get(&id).cloned(),
            );
            // invariant: a stream of the peer enters the queue when its
            // parts are made, and leaves the tables only when it is
            // reclaimed, which needs its reader to be done with it
            debug_assert!(
                parts.1.is_some(),
                "stream {id} to accept has no receiving part"
            );
            if parts.1.is_some() {
                if held {
                    // under the set's lock, before anyone reclaims it: its
                    // receiving part is not done before it is read
                    if let Some(part) = &parts.0 {
                        part.hold();
                    }
                    if let Some(part) = &parts.1 {
                        part.hold();
                    }
                }
                return Poll::Ready(Ok((id, parts)));
            }
        }
    }
}

/// The writer and reader of the parts `parts` of `id`, sharing `shared`.
#[allow(clippy::type_complexity)]
fn handles<Lc, K, Rs: StreamResets, P, H, Ro, E>(
    shared: &Arc<StreamSetShare<Lc, K, H, Rs, P, E>>,
    id: StreamId,
    parts: FoundParts<Lc, K, Rs, P>,
) -> (
    Option<StreamWriter<LockedStreamSendShare<Lc, K, Rs, P, H, E>, NoSendOptions>>,
    Option<StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E>>>,
)
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    let (sending, receiving) = parts;
    let writer = sending.map(|part| {
        StreamWriter::new(LockedStreamSendShare {
            part,
            shared: Arc::clone(shared),
            credential: Some(StreamWriterCredential::new(id)),
        })
    });
    let reader = receiving.map(|part| {
        StreamReader::new(LockedStreamReceiveShare {
            part,
            stream_id: id,
            shared: Arc::clone(shared),
            credential: Some(StreamReaderCredential::new(id)),
            role: PhantomData,
        })
    });
    (writer, reader)
}

/// The share of a stream's receiving part an established layer of the
/// locked set gives, on the side of the layer's selection `A`.
type ReceiveShareOf<Lc, K, Rs, P, H, E, A> =
    LockedStreamReceiveShare<Lc, K, Rs, P, H, <A as LayerSelection>::Role, E>;

/// Opening needs both parts of a bidirectional stream and the sending part
/// of a unidirectional one; the set makes them so.
fn expect_part<X>(part: Option<X>) -> X {
    // invariant: `create_local_stream` makes the sending part of every
    // stream it opens and the receiving part of a bidirectional one, and
    // a stream of the peer enters the queue with the parts it has
    part.unwrap_or_else(|| unreachable!("a stream is opened or accepted with its parts"))
}

/// A writer of the locked set, publishing through `H`.
type WriterOf<Lc, K, Rs, P, H, E> =
    StreamWriter<LockedStreamSendShare<Lc, K, Rs, P, H, E>, NoSendOptions>;

/// A reader of the locked set, publishing through `H`, of the side `Ro`.
type ReaderOf<Lc, K, Rs, P, H, Ro, E> =
    StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H, Ro, E>>;

/// Open a bidirectional stream on the set `shared` now, publishing through
/// a clone of its intake; at the limit, keep `waker` if one is given.
#[allow(clippy::type_complexity)] // a writer and a reader
fn open_bi_now<Lc, K, Rs, P, H, Ro, E>(
    shared: &Arc<StreamSetShare<Lc, K, H, Rs, P, E>>,
    waker: Option<&Waker>,
) -> Result<
    (
        WriterOf<Lc, K, Rs, P, H, E>,
        ReaderOf<Lc, K, Rs, P, H, Ro, E>,
    ),
    OpenRefused<Lc>,
>
where
    Rs: StreamResets,
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    let (id, parts) = shared.open_local(
        Directionality::Bidirectional,
        &mut shared.intake.clone(),
        waker,
        false,
    )?;
    let (writer, reader) = handles(shared, id, parts);
    Ok((expect_part(writer), expect_part(reader)))
}

/// Open a unidirectional stream on the set `shared` now, as
/// [`open_bi_now`] does.
#[allow(clippy::type_complexity)] // a writer or reader of seven type parameters
fn open_uni_now<Lc, K, Rs, P, H, Ro, E>(
    shared: &Arc<StreamSetShare<Lc, K, H, Rs, P, E>>,
    waker: Option<&Waker>,
) -> Result<WriterOf<Lc, K, Rs, P, H, E>, OpenRefused<Lc>>
where
    Rs: StreamResets,
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    let (id, parts) = shared.open_local(
        Directionality::Unidirectional,
        &mut shared.intake.clone(),
        waker,
        false,
    )?;
    let (writer, _) = handles::<_, _, _, _, _, Ro, _>(shared, id, parts);
    Ok(expect_part(writer))
}

/// The next bidirectional stream the peer opened on the set `shared`;
/// `Pending` with the waker of `cx` kept while none is there.
#[allow(clippy::type_complexity)] // a writer and a reader
fn poll_accept_bi<Lc, K, Rs, P, H, Ro, E>(
    shared: &Arc<StreamSetShare<Lc, K, H, Rs, P, E>>,
    cx: &mut Context<'_>,
) -> Poll<
    Result<
        (
            WriterOf<Lc, K, Rs, P, H, E>,
            ReaderOf<Lc, K, Rs, P, H, Ro, E>,
        ),
        LayerEndedError<Lc>,
    >,
>
where
    Rs: StreamResets,
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    shared
        .poll_accept(cx, Directionality::Bidirectional, false)
        .map(|accepted| match accepted {
            Ok((id, parts)) => {
                let (writer, reader) = handles(shared, id, parts);
                Ok((expect_part(writer), expect_part(reader)))
            }
            Err(end) => Err(LayerEndedError::new(end)),
        })
}

/// The next unidirectional stream the peer opened on the set `shared`, as
/// [`poll_accept_bi`] gives it.
#[allow(clippy::type_complexity)] // a writer or reader of seven type parameters
fn poll_accept_uni<Lc, K, Rs, P, H, Ro, E>(
    shared: &Arc<StreamSetShare<Lc, K, H, Rs, P, E>>,
    cx: &mut Context<'_>,
) -> Poll<Result<ReaderOf<Lc, K, Rs, P, H, Ro, E>, LayerEndedError<Lc>>>
where
    Rs: StreamResets,
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    shared
        .poll_accept(cx, Directionality::Unidirectional, false)
        .map(|accepted| match accepted {
            Ok((id, parts)) => {
                let (_, reader) = handles(shared, id, parts);
                Ok(expect_part(reader))
            }
            Err(end) => Err(LayerEndedError::new(end)),
        })
}

/// What a wait to open gives for one try: at the limit it waits.
fn waited<X, Lc>(opened: Result<X, OpenRefused<Lc>>) -> Poll<Result<X, LayerEndedError<Lc>>> {
    match opened {
        Ok(opened) => Poll::Ready(Ok(opened)),
        Err(OpenRefused::AtLimit) => Poll::Pending,
        Err(OpenRefused::Ended(end)) => Poll::Ready(Err(LayerEndedError::new(end))),
    }
}

/// What a try to open gives.
fn tried<X, Lc>(opened: Result<X, OpenRefused<Lc>>) -> Result<X, TryOpenStreamError<Lc>> {
    opened.map_err(|refused| match refused {
        OpenRefused::AtLimit => TryOpenStreamError::AtLimit,
        OpenRefused::Ended(end) => LayerEndedError::new(end).into(),
    })
}

/// The handle of the established layer `T`, `L`, `S`, `A` whose stream set
/// is the locked one: `K`, `Rs`, `P` and `E` are its parameters, as its
/// handle names them.
///
/// `Ie`, `Ic` and `Ir` are where the connection handle's state is in the
/// layer's lineage and in the connection node's, and where version 1's part
/// is in what the parts keep after the end; `Is` and `In` where the stream
/// set and the send strategy's intake are in the layer's lineage, `I` the
/// place of the stream intents in the composition's sum of intents.
impl<T, L, S, A> EstablishedLayerHandle<T, L, S, A>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
{
    /// Lend the layer once to `op`, with the stream set's shared state;
    /// otherwise how the layer ended.
    #[allow(clippy::type_complexity)] // the set of four type parameters
    fn with_set<R, K, H, Rs, P, E, Ie, Ic, Ir, Is>(
        &self,
        op: impl FnOnce(&Arc<StreamSetShare<CloseCauseOf<T, L>, K, H, Rs, P, E>>) -> R,
    ) -> Result<R, LayerEnd<CloseCauseOf<T, L>>>
    where
        Rs: StreamResets,
        SendTypes<T, L>: HostSendStrategyTypes,
        StreamSetFamilyOf<T>:
            ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
        StreamsOf<T, L>: StreamSet<
                CloseCauseOf<T, L>,
                SendTypes<T, L>,
                StreamResetsOfParts<L>,
                Handle = LockedStreamSetHandle<CloseCauseOf<T, L>, K, H, Rs, P, E>,
            >,
        RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
        for<'v> <L as LineageLists<'v, T>>::Established:
            GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<StreamsOf<T, L>, Is>,
        for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
    {
        self.lend_layer::<_, Ie, Ic, Ir>(|lineage, _| {
            let shared = lineage.get::<StreamsOf<T, L>, Is>().handle().shared;
            op(&shared)
        })
    }
}

/// The handle of an established layer whose stream set is the locked one
/// opens this side's streams with independent shares: each try, and each
/// poll of a wait, lends the layer once, takes the set's handle from it,
/// and publishes the streams' intents through the set's intake. What it
/// opens holds the set's shared state, apart from the connection, and the
/// credential itself.
impl<T, L, S, A, K, H, Rs, P, E, Ie, Ic, Ir, Is> OpenDetachedStreams<(Ie, Ic, Ir, Is)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    A: LayerSelection,
    Rs: StreamResets,
    E: SharedEvents,
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            Handle = LockedStreamSetHandle<CloseCauseOf<T, L>, K, H, Rs, P, E>,
        >,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<StreamsOf<T, L>, Is>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
{
    type SendShare = LockedStreamSendShare<CloseCauseOf<T, L>, K, Rs, P, H, E>;
    type ReceiveShare = ReceiveShareOf<CloseCauseOf<T, L>, K, Rs, P, H, E, A>;
    type CloseCause = CloseCauseOf<T, L>;

    fn open_bi_detached(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<CloseCauseOf<T, L>>,
        >,
    > {
        poll_fn(move |cx| {
            self.with_set::<_, K, H, Rs, P, E, Ie, Ic, Ir, Is>(|shared| {
                waited(open_bi_now(shared, Some(cx.waker())))
            })
            .unwrap_or_else(|end| Poll::Ready(Err(LayerEndedError::new(end))))
        })
    }

    fn open_uni_detached(
        &self,
    ) -> impl Future<
        Output = Result<
            StreamWriter<Self::SendShare, NoSendOptions>,
            LayerEndedError<CloseCauseOf<T, L>>,
        >,
    > {
        poll_fn(move |cx| {
            self.with_set::<_, K, H, Rs, P, E, Ie, Ic, Ir, Is>(|shared| {
                waited(open_uni_now::<_, _, _, _, _, A::Role, _>(
                    shared,
                    Some(cx.waker()),
                ))
            })
            .unwrap_or_else(|end| Poll::Ready(Err(LayerEndedError::new(end))))
        })
    }

    fn try_open_bi_detached(
        &self,
    ) -> Result<
        (
            StreamWriter<Self::SendShare, NoSendOptions>,
            StreamReader<Self::ReceiveShare>,
        ),
        TryOpenStreamError<CloseCauseOf<T, L>>,
    > {
        self.with_set::<_, K, H, Rs, P, E, Ie, Ic, Ir, Is>(|shared| {
            tried(open_bi_now(shared, None))
        })
        .unwrap_or_else(|end| Err(LayerEndedError::new(end).into()))
    }

    fn try_open_uni_detached(
        &self,
    ) -> Result<StreamWriter<Self::SendShare, NoSendOptions>, TryOpenStreamError<CloseCauseOf<T, L>>>
    {
        self.with_set::<_, K, H, Rs, P, E, Ie, Ic, Ir, Is>(|shared| {
            tried(open_uni_now::<_, _, _, _, _, A::Role, _>(shared, None))
        })
        .unwrap_or_else(|end| Err(LayerEndedError::new(end).into()))
    }
}

/// The handle of an established layer whose stream set is the locked one
/// accepts the peer's streams with independent shares from the set's
/// queues, in the order their first frames arrived; each poll lends the
/// layer once, and the places are as for opening.
impl<T, L, S, A, K, H, Rs, P, E, Ie, Ic, Ir, Is> AcceptDetachedStreams<(Ie, Ic, Ir, Is)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    A: LayerSelection,
    Rs: StreamResets,
    E: SharedEvents,
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            Handle = LockedStreamSetHandle<CloseCauseOf<T, L>, K, H, Rs, P, E>,
        >,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<StreamsOf<T, L>, Is>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
{
    type SendShare = LockedStreamSendShare<CloseCauseOf<T, L>, K, Rs, P, H, E>;
    type ReceiveShare = ReceiveShareOf<CloseCauseOf<T, L>, K, Rs, P, H, E, A>;
    type CloseCause = CloseCauseOf<T, L>;

    fn accept_bi_detached(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<CloseCauseOf<T, L>>,
        >,
    > {
        poll_fn(move |cx| {
            self.with_set::<_, K, H, Rs, P, E, Ie, Ic, Ir, Is>(|shared| poll_accept_bi(shared, cx))
                .unwrap_or_else(|end| Poll::Ready(Err(LayerEndedError::new(end))))
        })
    }

    fn accept_uni_detached(
        &self,
    ) -> impl Future<
        Output = Result<StreamReader<Self::ReceiveShare>, LayerEndedError<CloseCauseOf<T, L>>>,
    > {
        poll_fn(move |cx| {
            self.with_set::<_, K, H, Rs, P, E, Ie, Ic, Ir, Is>(|shared| poll_accept_uni(shared, cx))
                .unwrap_or_else(|end| Poll::Ready(Err(LayerEndedError::new(end))))
        })
    }
}
