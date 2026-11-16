//! The application's side of the default stream set: the shares of a
//! stream's parts its writers and readers hold
//! ([`LockedStreamSendShare`], [`LockedStreamReceiveShare`]), and opening
//! and accepting streams on the handle of its established layer.
//!
//! A share holds the part of the stream it is of, the set's shared state
//! and the handle it publishes the stream's intents through, with the place
//! of the stream intent fixed. Every operation changes the part under its
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
//! - Everything waiting ends when the layer does.
//!
//! Dropping a share gives the part up: the writer's tells the sending part
//! its writer was abandoned, the reader's that its reader was dropped; the
//! parts' termination policies decide what follows (streams.md
//! «方向句柄Drop与终结策略»).

use core::{
    future::{Future, poll_fn, ready},
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use std::sync::Arc;

use bytes::{Buf, BufMut};
use nitori_io::{Read, ReadChunk};
use sakuya_stream::{
    connection::{LayerEnd, LayerEndedError},
    receive::{
        read::ReadError, read::ReadOutcome, stop::StopError, termination::ReceiveTerminationPolicy,
    },
    send::{
        SendTerminalState, StreamResetError,
        finish::{CloseError, ResetError},
        termination::SendTerminationPolicy,
        write::{FlushError, WriteError, WriteOutcome, WriteReport, WriteWait},
    },
    send_options::{
        NoSendOptions, SendOptions, destination::AnyActiveLinkPath, urgency::SendUrgency,
    },
};
use sakuya_wire::{
    v1::{
        application_error::ApplicationErrorCode,
        stream_id::{Directionality, StreamId},
    },
    var_int::VarInt,
};

use super::{
    ConnectionReceive, LockedStreamEnd, LockedStreamSetHandle, ReceivingEnd, ReceivingPart,
    SendCompositionOf, SendingEnd, SendingPart, SetState, StreamSetShare, lock, send_composition,
};
use crate::{
    send_strategy::{IntentTicketResize, IntentTicketWithdraw, SendIntentIntake, SharedPublishTo},
    v1::{
        application_handles::{
            connection::keep_waker,
            established_layer::{
                AcceptStreams, EstablishedLayerHandle, OpenStreams, TryOpenStreamError,
            },
            stream::{AllAcknowledgedError, StreamRead, StreamReader, StreamWrite, StreamWriter},
        },
        streams::{
            resets::StreamResets,
            send::{StreamIntent, StreamIntentHandle},
        },
    },
};
use sakuya_stream::{
    connection_send_credit::ConnectionSendFlowController,
    receive::composition::DefaultReceiveComposition,
};

#[cfg(test)]
mod tests;

/// The reason the termination policy of a sending part gives for a write
/// limit.
type WriteLimitReasonOf<Rs, P> = <SendCompositionOf<Rs, P> as SendTerminationPolicy<
    <Rs as StreamResets>::Local,
>>::WriteLimitReason;

/// The failure of a read of a receiving part of the default set.
type ReadErrorOf<Lc, Rs> = ReadError<
    <DefaultReceiveComposition as ReceiveTerminationPolicy<<Rs as StreamResets>::Remote>>::Reason,
    Lc,
    <Rs as StreamResets>::Remote,
>;

/// A block a read of a receiving part gives.
type ChunkOf =
    <DefaultReceiveComposition as sakuya_stream::receive_buffer::StreamReceiveBuffer>::Chunk;

// ---- the shares ----

/// This side's share of a stream's sending part in a [`LockedStreamSet`]
/// (`LockedStreamSendShare`), which a [`StreamWriter`] holds: the part,
/// the set's shared state, and the handle `H` its intents are published
/// through. It cannot be cloned.
///
/// [`LockedStreamSet`]: super::LockedStreamSet
pub struct LockedStreamSendShare<Lc, K, Rs: StreamResets, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    part: SendingPart<Lc, K, Rs, P>,
    shared: Arc<StreamSetShare<Lc, K, Rs, P>>,
    publish: H,
}

/// This side's share of a stream's receiving part in a [`LockedStreamSet`]
/// (`LockedStreamReceiveShare`), which a [`StreamReader`] holds, as
/// [`LockedStreamSendShare`] is of a sending part.
///
/// [`LockedStreamSet`]: super::LockedStreamSet
pub struct LockedStreamReceiveShare<Lc, K, Rs: StreamResets, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    part: ReceivingPart<Lc, K, Rs, P>,
    stream_id: StreamId,
    shared: Arc<StreamSetShare<Lc, K, Rs, P>>,
    publish: H,
}

/// Nothing of a share is pinned.
impl<Lc, K, Rs: StreamResets, P, H> Unpin for LockedStreamSendShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
}

/// Nothing of a share is pinned.
impl<Lc, K, Rs: StreamResets, P, H> Unpin for LockedStreamReceiveShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
}

impl<Lc, K, Rs: StreamResets, P, H> core::fmt::Debug for LockedStreamSendShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockedStreamSendShare")
            .finish_non_exhaustive()
    }
}

impl<Lc, K, Rs: StreamResets, P, H> core::fmt::Debug for LockedStreamReceiveShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LockedStreamReceiveShare")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl<Lc, K, Rs: StreamResets, P, H> LockedStreamSendShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    /// Change the part with `change` under its lock, and bring its intents
    /// to what is due then.
    fn with_part<R>(&self, change: impl FnOnce(&mut SendingEnd<Lc, K, Rs, P>) -> R) -> R {
        let mut end = self.part.lock();
        let result = change(&mut end);
        end.sync_intents(&self.publish);
        result
    }
}

/// The writer gives the stream up when it is dropped.
impl<Lc, K, Rs: StreamResets, P, H> Drop for LockedStreamSendShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    fn drop(&mut self) {
        self.with_part(|end| {
            end.sender.on_writer_abandoned();
            end.writer = None;
        });
    }
}

/// The sending part's operations, under its lock; see the
/// [module documentation](self).
impl<Lc, K, Rs: StreamResets, P, H> StreamWrite for LockedStreamSendShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
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
        let marker = SendOptions::new(parameters.clone(), *destination);
        loop {
            let outcome = self.with_part(|end| {
                let outcome = end.sender.write(input, &marker);
                if let Ok(WriteOutcome::Wait(wait)) = &outcome
                    && *wait != WriteWait::ConnectionCredit
                {
                    // the stream's limit or its policy holds it back: a
                    // MAX_STREAM_DATA, a STOP_SENDING or the layer's end
                    // wakes it, under this lock
                    end.writer = Some(cx.waker().clone());
                }
                outcome
            });
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
            let limit = connection.limit();
            self.shared.with_set(&self.publish, |set| {
                set.connection.data_blocked_signal.on_write_blocked(limit);
            });
            if connection.available() == VarInt::ZERO {
                return Poll::Pending;
            }
        }
    }

    fn close(&mut self) -> Result<(), CloseError<Lc>> {
        self.with_part(|end| end.sender.close())
    }

    fn reset(&mut self, code: ApplicationErrorCode) -> Result<(), ResetError<Lc>> {
        self.with_part(|end| Rs::reset(&mut end.sender, code))
    }

    /// Writes go into the send buffer at once: nothing is held back, and it
    /// is done at once.
    fn flush(&mut self) -> impl Future<Output = Result<(), FlushError<Lc>>> {
        ready(self.part.lock().sender.flush())
    }

    fn all_acknowledged(&mut self) -> impl Future<Output = Result<(), AllAcknowledgedError<Lc>>> {
        poll_fn(|cx| {
            let mut end = self.part.lock();
            match end.sender.terminal_state() {
                Some(SendTerminalState::DataRecvd) => return Poll::Ready(Ok(())),
                Some(SendTerminalState::ResetRecvd) => {
                    return Poll::Ready(Err(StreamResetError.into()));
                }
                None => {}
            }
            match end.sender.flush() {
                Err(FlushError::LayerEnded { source }) => return Poll::Ready(Err(source.into())),
                Err(FlushError::Reset { source }) => return Poll::Ready(Err(source.into())),
                Ok(()) => {}
            }
            // an acknowledgment, a STOP_SENDING or the layer's end wakes it
            end.writer = Some(cx.waker().clone());
            Poll::Pending
        })
    }
}

impl<Lc, K, Rs: StreamResets, P, H> LockedStreamReceiveShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    /// Change the part with `change` under its lock; then, with the receive
    /// flow controller's lock taken under it, report what the stream
    /// released, and bring the intents of the connection's receiving and of
    /// the part to what is due.
    fn with_part<R>(&self, change: impl FnOnce(&mut ReceivingEnd<Lc, K, Rs, P>) -> R) -> R {
        let mut end = self.part.lock();
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
            connection.sync_intents(&self.publish);
        }
        end.sync_intents(self.stream_id, &self.publish);
        result
    }

    /// Read with `read`, which gives what the receiving part gives; keep
    /// the waker of `cx` when it has to wait.
    fn poll_read_with<R>(
        &mut self,
        cx: &mut Context<'_>,
        read: impl FnOnce(
            &mut ReceivingEnd<Lc, K, Rs, P>,
        ) -> Result<ReadOutcome<R>, ReadErrorOf<Lc, Rs>>,
    ) -> Poll<Result<ReadOutcome<R>, ReadErrorOf<Lc, Rs>>> {
        self.with_part(|end| match read(end) {
            Ok(ReadOutcome::Wait) => {
                // a STREAM or RESET_STREAM frame, or the layer's end, wakes
                // it, under this lock
                end.reader = Some(cx.waker().clone());
                Poll::Pending
            }
            other => Poll::Ready(other),
        })
    }

    /// Read into `destination`; `Ok(0)` at the end of the stream or for no
    /// room, as nitori_io's `Read` has it.
    fn poll_read_into<O: BufMut + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, ReadErrorOf<Lc, Rs>>> {
        self.poll_read_with(cx, |end| end.receiver.read_into(destination))
            .map_ok(|outcome| match outcome {
                ReadOutcome::Data(copied) => copied.get(),
                ReadOutcome::NoProgress | ReadOutcome::End | ReadOutcome::Wait => 0,
            })
    }

    /// Read a block of at most `maximum` bytes; `None` at the end of the
    /// stream.
    fn poll_read_chunk(
        &mut self,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<ChunkOf>, ReadErrorOf<Lc, Rs>>> {
        self.poll_read_with(cx, |end| end.receiver.read_chunk(maximum))
            .map_ok(|outcome| match outcome {
                ReadOutcome::Data(chunk) => Some(chunk),
                // invariant: a block read takes no target that can be full
                ReadOutcome::NoProgress | ReadOutcome::End | ReadOutcome::Wait => None,
            })
    }
}

/// The reader gives the reading up when it is dropped.
impl<Lc, K, Rs: StreamResets, P, H> Drop for LockedStreamReceiveShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    fn drop(&mut self) {
        self.with_part(|end| {
            end.receiver.reader_dropped();
            end.reader = None;
        });
    }
}

/// The receiving part's STOP, under its lock.
impl<Lc, K, Rs: StreamResets, P, H> StreamRead for LockedStreamReceiveShare<Lc, K, Rs, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    type CloseCause = Lc;

    fn stop(&mut self, code: ApplicationErrorCode) -> Result<(), StopError<Lc>> {
        self.with_part(|end| end.receiver.stop(code))
    }
}

/// A reader of the default set reads its receiving part.
impl<Lc, K, Rs: StreamResets, P, H> Read for StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H>>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
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
            .poll_read_into(cx, destination)
    }
}

/// A reader of the default set reads blocks of its receiving part, cut at
/// the maximum.
impl<Lc, K, Rs: StreamResets, P, H> ReadChunk
    for StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H>>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
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
            .poll_read_chunk(cx, maximum)
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
enum OpenRefused<Lc> {
    /// The peer's limit allows no more streams of the type.
    AtLimit,
    /// The layer ended.
    Ended(LayerEnd<Lc>),
}

impl<Lc, K, Rs: StreamResets, P> StreamSetShare<Lc, K, Rs, P>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
{
    /// Make the parts of `id`, a stream this side opens: a bidirectional
    /// one gets both, a unidirectional one its sending part.
    fn create_local_stream(
        &self,
        set: &mut SetState<Lc, K, Rs, P>,
        id: StreamId,
    ) -> FoundParts<Lc, K, Rs, P> {
        let sender = sakuya_stream::send::StreamSender::new(
            id,
            self.facts.send_limit(id),
            send_composition::<Rs, P>(&self.config),
            Arc::clone(&self.connection_send),
        );
        let sending = Arc::new(LockedStreamEnd::new(SendingEnd::new(sender)));
        set.senders.insert(id, Arc::clone(&sending));
        let receiving = (id.directionality() == Directionality::Bidirectional).then(|| {
            let window = self.facts.receive_window(id);
            let receiver = sakuya_stream::receive::StreamReceiver::new(
                DefaultReceiveComposition::with_window_and_abandon_code(
                    window,
                    self.config.receive_abandon_code,
                ),
                window,
            );
            let receiving = Arc::new(LockedStreamEnd::new(ReceivingEnd::new(receiver)));
            set.receivers.insert(id, Arc::clone(&receiving));
            receiving
        });
        (Some(sending), receiving)
    }

    /// Open the next stream of `directionality` of this side under the
    /// set's lock; at the limit, keep `waker` if one is given and have
    /// STREAMS_BLOCKED sent.
    fn open_local<H: StreamIntentHandle<P, K>>(
        &self,
        directionality: Directionality,
        publish: &H,
        waker: Option<&Waker>,
    ) -> Result<FoundStream<Lc, K, Rs, P>, OpenRefused<Lc>> {
        self.with_set(publish, |set| {
            if let Some(end) = &set.end {
                return Err(OpenRefused::Ended(end.clone()));
            }
            match set.ledger.open_local(directionality) {
                Ok(id) => Ok((id, self.create_local_stream(set, id))),
                Err(_) => {
                    if let Some(waker) = waker {
                        keep_waker(set.open_wakers.get_mut(directionality), waker);
                    }
                    Err(OpenRefused::AtLimit)
                }
            }
        })
    }

    /// The next stream of `directionality` the peer opened, under the
    /// set's lock; `Pending` with the waker of `cx` kept while none is
    /// there.
    #[allow(clippy::type_complexity)] // a stream of four type parameters
    fn poll_accept(
        &self,
        cx: &mut Context<'_>,
        directionality: Directionality,
    ) -> Poll<Result<FoundStream<Lc, K, Rs, P>, LayerEnd<Lc>>> {
        let mut set = lock(&self.set);
        if let Some(end) = &set.end {
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
                return Poll::Ready(Ok((id, parts)));
            }
        }
    }
}

/// The writer and reader of the parts `parts` of `id`, sharing `shared`
/// and publishing through `publish`.
#[allow(clippy::type_complexity)]
fn handles<Lc, K, Rs: StreamResets, P, H>(
    shared: &Arc<StreamSetShare<Lc, K, Rs, P>>,
    publish: &H,
    id: StreamId,
    parts: FoundParts<Lc, K, Rs, P>,
) -> (
    Option<StreamWriter<LockedStreamSendShare<Lc, K, Rs, P, H>, NoSendOptions>>,
    Option<StreamReader<LockedStreamReceiveShare<Lc, K, Rs, P, H>>>,
)
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    let (sending, receiving) = parts;
    let writer = sending.map(|part| {
        StreamWriter::new(LockedStreamSendShare {
            part,
            shared: Arc::clone(shared),
            publish: publish.clone(),
        })
    });
    let reader = receiving.map(|part| {
        StreamReader::new(LockedStreamReceiveShare {
            part,
            stream_id: id,
            shared: Arc::clone(shared),
            publish: publish.clone(),
        })
    });
    (writer, reader)
}

/// The share of a stream's sending part an established layer of the
/// default set gives, publishing at the place `I` through the intake `N`.
type SendShareOf<Lc, K, Rs, P, N, I> = LockedStreamSendShare<
    Lc,
    K,
    Rs,
    P,
    <N as SendIntentIntake<AnyActiveLinkPath>>::Handle<StreamIntent<P>, I>,
>;

/// The share of a stream's receiving part, as [`SendShareOf`].
type ReceiveShareOf<Lc, K, Rs, P, N, I> = LockedStreamReceiveShare<
    Lc,
    K,
    Rs,
    P,
    <N as SendIntentIntake<AnyActiveLinkPath>>::Handle<StreamIntent<P>, I>,
>;

/// Opening needs both parts of a bidirectional stream and the sending part
/// of a unidirectional one; the set makes them so.
fn expect_part<X>(part: Option<X>) -> X {
    // invariant: `create_local_stream` makes the sending part of every
    // stream it opens and the receiving part of a bidirectional one, and
    // a stream of the peer enters the queue with the parts it has
    part.unwrap_or_else(|| unreachable!("a stream is opened or accepted with its parts"))
}

/// The handle of an established layer of the default set opens this
/// side's streams through the set's handle, and publishes their intents at
/// the place `I` through the intake `N`.
impl<Lc, K, Rs: StreamResets, P, N, A, I> OpenStreams<I>
    for EstablishedLayerHandle<LockedStreamSetHandle<Lc, K, Rs, P>, N, A, Lc>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    N: SendIntentIntake<AnyActiveLinkPath> + SharedPublishTo<StreamIntent<P>, AnyActiveLinkPath, I>,
    N::Handle<StreamIntent<P>, I>: StreamIntentHandle<P, K>,
{
    type SendShare = SendShareOf<Lc, K, Rs, P, N, I>;
    type ReceiveShare = ReceiveShareOf<Lc, K, Rs, P, N, I>;
    type CloseCause = Lc;

    fn open_bi(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<Lc>,
        >,
    > {
        let publish = self.intake.handle::<StreamIntent<P>, I>();
        let shared = &self.streams.shared;
        poll_fn(move |cx| {
            match shared.open_local(Directionality::Bidirectional, &publish, Some(cx.waker())) {
                Ok((id, parts)) => {
                    let (writer, reader) = handles(shared, &publish, id, parts);
                    Poll::Ready(Ok((expect_part(writer), expect_part(reader))))
                }
                Err(OpenRefused::AtLimit) => Poll::Pending,
                Err(OpenRefused::Ended(end)) => Poll::Ready(Err(LayerEndedError::new(end))),
            }
        })
    }

    fn open_uni(
        &self,
    ) -> impl Future<Output = Result<StreamWriter<Self::SendShare, NoSendOptions>, LayerEndedError<Lc>>>
    {
        let publish = self.intake.handle::<StreamIntent<P>, I>();
        let shared = &self.streams.shared;
        poll_fn(move |cx| {
            match shared.open_local(Directionality::Unidirectional, &publish, Some(cx.waker())) {
                Ok((id, parts)) => {
                    let (writer, _) = handles(shared, &publish, id, parts);
                    Poll::Ready(Ok(expect_part(writer)))
                }
                Err(OpenRefused::AtLimit) => Poll::Pending,
                Err(OpenRefused::Ended(end)) => Poll::Ready(Err(LayerEndedError::new(end))),
            }
        })
    }

    fn try_open_bi(
        &self,
    ) -> Result<
        (
            StreamWriter<Self::SendShare, NoSendOptions>,
            StreamReader<Self::ReceiveShare>,
        ),
        TryOpenStreamError<Lc>,
    > {
        let publish = self.intake.handle::<StreamIntent<P>, I>();
        let shared = &self.streams.shared;
        match shared.open_local(Directionality::Bidirectional, &publish, None) {
            Ok((id, parts)) => {
                let (writer, reader) = handles(shared, &publish, id, parts);
                Ok((expect_part(writer), expect_part(reader)))
            }
            Err(OpenRefused::AtLimit) => Err(TryOpenStreamError::AtLimit),
            Err(OpenRefused::Ended(end)) => Err(LayerEndedError::new(end).into()),
        }
    }

    fn try_open_uni(
        &self,
    ) -> Result<StreamWriter<Self::SendShare, NoSendOptions>, TryOpenStreamError<Lc>> {
        let publish = self.intake.handle::<StreamIntent<P>, I>();
        let shared = &self.streams.shared;
        match shared.open_local(Directionality::Unidirectional, &publish, None) {
            Ok((id, parts)) => {
                let (writer, _) = handles(shared, &publish, id, parts);
                Ok(expect_part(writer))
            }
            Err(OpenRefused::AtLimit) => Err(TryOpenStreamError::AtLimit),
            Err(OpenRefused::Ended(end)) => Err(LayerEndedError::new(end).into()),
        }
    }
}

/// The handle of an established layer of the default set accepts the
/// peer's streams from the set's queues, in the order their first frames
/// arrived.
impl<Lc, K, Rs: StreamResets, P, N, A, I> AcceptStreams<I>
    for EstablishedLayerHandle<LockedStreamSetHandle<Lc, K, Rs, P>, N, A, Lc>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    N: SendIntentIntake<AnyActiveLinkPath> + SharedPublishTo<StreamIntent<P>, AnyActiveLinkPath, I>,
    N::Handle<StreamIntent<P>, I>: StreamIntentHandle<P, K>,
{
    type SendShare = SendShareOf<Lc, K, Rs, P, N, I>;
    type ReceiveShare = ReceiveShareOf<Lc, K, Rs, P, N, I>;
    type CloseCause = Lc;

    fn accept_bi(
        &self,
    ) -> impl Future<
        Output = Result<
            (
                StreamWriter<Self::SendShare, NoSendOptions>,
                StreamReader<Self::ReceiveShare>,
            ),
            LayerEndedError<Lc>,
        >,
    > {
        let publish = self.intake.handle::<StreamIntent<P>, I>();
        let shared = &self.streams.shared;
        poll_fn(move |cx| {
            shared
                .poll_accept(cx, Directionality::Bidirectional)
                .map(|accepted| match accepted {
                    Ok((id, parts)) => {
                        let (writer, reader) = handles(shared, &publish, id, parts);
                        Ok((expect_part(writer), expect_part(reader)))
                    }
                    Err(end) => Err(LayerEndedError::new(end)),
                })
        })
    }

    fn accept_uni(
        &self,
    ) -> impl Future<Output = Result<StreamReader<Self::ReceiveShare>, LayerEndedError<Lc>>> {
        let publish = self.intake.handle::<StreamIntent<P>, I>();
        let shared = &self.streams.shared;
        poll_fn(move |cx| {
            shared
                .poll_accept(cx, Directionality::Unidirectional)
                .map(|accepted| match accepted {
                    Ok((id, parts)) => {
                        let (_, reader) = handles(shared, &publish, id, parts);
                        Ok(expect_part(reader))
                    }
                    Err(end) => Err(LayerEndedError::new(end)),
                })
        })
    }
}
