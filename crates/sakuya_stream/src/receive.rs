//! The stream receive component: the per-stream receive direction of a
//! connection.
//!
//! A [`StreamReceiver`] takes the frames that affect the receive direction of
//! one stream — STREAM, the peer's resets and `STREAM_DATA_BLOCKED` — already
//! parsed and attributed to the stream, and the operations of the stream
//! reader: reads, the local STOP request and the reader being dropped. It
//! composes three contracts that one type `C` implements: the receive buffer
//! ([`StreamReceiveBuffer`]), the receive flow control policy
//! ([`ReceiveFlowControlPolicy`]) and the receive termination policy
//! ([`ReceiveTerminationPolicy`]). The type may hold three independent
//! components or let the buffer double as the flow control policy; it must
//! make them work on the same stream.
//!
//! The receiver is also generic over the type `F` of its reset facts, a
//! [`RemoteResetFacts`]: what a reset of the peer states and how far the peer
//! still owes data after it. [`RemoteReset`], the default, is the reset of
//! RFC 9000, delivered with
//! [`on_reset_stream`](StreamReceiver::on_reset_stream). Other kinds of reset
//! come in through [`on_remote_reset`](StreamReceiver::on_remote_reset).
//!
//! # Exclusive operations
//!
//! Every method takes `&mut self`: one operation has the whole receive
//! direction to itself, and buffer and policy calls happen inside it. A frame
//! is checked before anything changes: the component works out the accounted
//! end the frame would reach from the buffer's current one, checks the final
//! size rules and the stream limit, and records the increase with the
//! [`ConnectionReceiveFlowController`] passed in; only a frame that passed
//! every check is handed to the receive buffer. A frame that fails a check
//! leaves nothing of itself behind.
//!
//! # Violations and connection closure
//!
//! The frame methods return the violations of their own frame (see
//! [`violation`]) and keep no failure the application can see. After a
//! violation the stream waits for the connection to close
//! ([`connection_closed`](StreamReceiver::connection_closed)), which the
//! caller does for the first reason the connection records. In between, the
//! stream exposes no new result to the application: a read does not complete,
//! and further frames are ignored. Once the connection has closed, every
//! operation of the application fails with [`ConnectionClosedError`], which
//! carries the reason. The connection side pushes the reason into each stream
//! in the poll that records it; a stream never reads it from anywhere.
//!
//! # Three independent dimensions
//!
//! - Remote end facts: the final size (kept by the buffer) and the reset
//!   facts, which the first reset establishes and later ones are merged into
//!   ([`RemoteResetFacts::merge`]). They say how far the peer still owes data
//!   ([`RemoteResetFacts::owed_end`]); a `RESET_STREAM` owes nothing.
//! - Local delivery limits: the data acceptance limit (`acceptance_limit`),
//!   which bounds the new payload the buffer keeps, and the delivery limit
//!   (`delivery_limit`), which bounds delivery to the application. Each
//!   follows reception ([`BoundaryMode::Following`]) until the receive
//!   termination policy fixes it ([`BoundaryMode::Fixed`]); a fixed limit can
//!   only stay or tighten.
//! - The committed read result: once a read has returned end of stream or a
//!   terminal error, later frames do not change it.
//!
//! What the peer still owes is not a local truncation: it says which gaps
//! are still worth waiting for, never how far delivery may go.
//!
//! Waiting and waking, the asynchronous reader, sending `STOP_SENDING` and
//! `MAX_STREAM_DATA`, and propagating connection errors are left to the
//! surrounding composition; this module offers the synchronous entry points
//! they call. The limit actions ([`termination::BoundaryAction`]) are
//! provisional.
//!
//! [`StreamReceiveBuffer`]: crate::receive_buffer::StreamReceiveBuffer
use crate::connection::{CloseReason, ConnectionClosedError};
use crate::connection_receive_flow::{
    ConnectionReceiveFlowController, RecordReleaseError, RecordUsageError,
};
use crate::receive_buffer::{StreamDataInput, StreamReceiveBuffer, offset_add, span};
use crate::stream_end::{BeyondFinalSizeError, FinalSizeChangeError};
use bytes::Bytes;
use core::error::Error;
use flow_control::{ReceiveFlowControlPolicy, ReceiveFlowEvent, ReceiveFlowView};
use read::{ReadError, SharedTerminationReason};
use received_ranges::ReceivedRanges;
use remote_reset::{RemoteReset, RemoteResetFacts};
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::var_int::VarInt;
use snafu::ResultExt;
use termination::{ReceiveTerminationPolicy, ResetPresentation, TerminationEvent, TerminationView};
use violation::{
    ConflictSnafu, FinalSizeBelowReceivedError, MalformedSnafu, OffsetOverflowSnafu,
    OnRemoteResetError, OnResetStreamError, OnStreamFrameError, StreamLimitExceededError,
};

pub mod flow_control;
pub mod read;
mod received_ranges;
pub mod remote_reset;
pub mod stop;
pub mod termination;
pub mod violation;

/// A STREAM frame of the stream ([RFC 9000 §19.8]).
///
/// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamFrame {
    /// The offset of the first byte of `data`.
    pub offset: VarInt,
    /// The stream data the frame carries.
    pub data: Bytes,
    /// Whether the frame carries FIN, stating `offset + data.len()` as the
    /// final size.
    pub fin: bool,
}

/// A `RESET_STREAM` frame of the stream ([RFC 9000 §19.4]).
///
/// [RFC 9000 §19.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.4
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetStreamFrame {
    /// The application protocol error code.
    pub code: ApplicationErrorCode,
    /// The final size of the stream.
    pub final_size: VarInt,
}

/// The mode of a local delivery limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BoundaryMode {
    /// The limit follows reception and bounds nothing locally.
    Following,
    /// The limit is fixed at this offset; it can only stay or tighten.
    ///
    /// Fixing a following limit is a real change even when the value equals
    /// the current accounted end.
    Fixed(VarInt),
}

impl BoundaryMode {
    /// The offset the limit bounds at: the fixed value, or [`VarInt::MAX`]
    /// while following.
    pub fn effective_limit(self) -> VarInt {
        match self {
            Self::Following => VarInt::MAX,
            Self::Fixed(limit) => limit,
        }
    }
}

/// A local reason, and the event during which it took effect.
///
/// `X` is the change a later reset can make to the reset facts
/// ([`RemoteResetFacts::Change`]), which the event may carry.
#[derive(Debug)]
struct Applied<R, X> {
    reason: SharedTerminationReason<R>,
    trigger: TerminationEvent<X>,
}

impl<R, X: Clone> Clone for Applied<R, X> {
    fn clone(&self) -> Self {
        Self {
            reason: self.reason.clone(),
            trigger: self.trigger.clone(),
        }
    }
}

/// A local delivery limit with the reason it was fixed for.
#[derive(Clone, Debug)]
enum Boundary<R, X> {
    Following,
    Fixed {
        limit: VarInt,
        applied: Applied<R, X>,
    },
}

impl<R, X> Boundary<R, X> {
    fn mode(&self) -> BoundaryMode {
        match self {
            Self::Following => BoundaryMode::Following,
            Self::Fixed { limit, .. } => BoundaryMode::Fixed(*limit),
        }
    }

    fn limit(&self) -> VarInt {
        self.mode().effective_limit()
    }
}

/// The local STOP request:
///
/// ```text
///                  stop(code)               sent
///   NotRequested ──────────────▶ Pending ─────────▶ Sent
/// ```
#[derive(Clone, Copy, Debug)]
enum StopRequest {
    /// No request is installed.
    NotRequested,
    /// A request with this code is installed and not yet sent.
    Pending(ApplicationErrorCode),
    /// The request with this code was sent.
    Sent(ApplicationErrorCode),
}

impl StopRequest {
    fn code(self) -> Option<ApplicationErrorCode> {
        match self {
            Self::NotRequested => None,
            Self::Pending(code) | Self::Sent(code) => Some(code),
        }
    }
}

/// What happened to the receive buffer and its payload:
///
/// ```text
///          destroy (policy, reader drop, terminal error, connection closed)
///   Live ───────────────────────────────────────────────────────────────▶ Destroyed
/// ```
///
/// A destroyed buffer keeps its first cause. Destroying releases the data
/// only: the ranges the frames stated stay recorded in the receiver, so
/// reception can still complete.
#[derive(Clone, Debug)]
enum BufferPhase<R, X> {
    /// The buffer holds payload for delivery.
    Live,
    /// The buffer was destroyed.
    Destroyed(Destruction<R, X>),
}

/// How far the connection's end has reached this stream:
///
/// ```text
///            frame violation               connection_closed
///   Open ───────────────────▶ Violated ───────────────────────▶ Closed
///     │                                                           ▲
///     └──────────────────── connection_closed ────────────────────┘
/// ```
///
/// `Violated` is the stream between a violation returned by a frame method
/// and the connection's closure: the caller is closing the connection with
/// the violation, and the stream exposes no new result to the application
/// meanwhile. `Closed` is final: the closure is the highest-priority result
/// of every later operation, and the buffer is destroyed.
#[derive(Clone, Debug)]
enum ConnectionPhase {
    /// Nothing ended the connection as far as this stream knows.
    Open,
    /// A frame violated the protocol; the stream waits for the connection to
    /// close.
    Violated,
    /// The connection closed; the first reason is kept.
    Closed(ConnectionClosedError),
}

/// Why the receive buffer was destroyed.
#[derive(Clone, Debug)]
enum Destruction<R, X> {
    /// The receive termination policy destroyed it for this reason.
    Policy(Applied<R, X>),
    /// The mechanism destroyed it: the reader was dropped or a read
    /// committed a terminal error.
    Forced,
}

/// The reader and its result:
///
/// ```text
///          end or terminal error                 drop
///   Open ────────────────────────▶ Committed ───────────▶ ReaderDropped
///     │                                                    ▲ (committed)
///     └──────────────────────── drop ──────────────────────┘ (not committed)
/// ```
#[derive(Clone, Debug)]
enum Reading<R, F: RemoteResetFacts> {
    /// The reader may read; no result is committed.
    Open,
    /// A read committed this result; repeated reads return it.
    Committed(Committed<R, F>),
    /// The reader was dropped; no more reads happen.
    ReaderDropped {
        /// Whether a read had committed a result before.
        result_committed: bool,
    },
}

#[derive(Clone, Debug)]
enum Committed<R, F: RemoteResetFacts> {
    End,
    Error(ReadError<R, F>),
}

/// The receive direction of one stream.
///
/// `C` implements the receive buffer, the receive flow control policy and
/// the receive termination policy for this stream. `F` is the type of the
/// reset facts the stream keeps; it decides which resets the stream takes.
/// See the [module documentation](self) for the processing model.
#[derive(Debug)]
pub struct StreamReceiver<C: ReceiveTerminationPolicy<F>, F: RemoteResetFacts = RemoteReset> {
    parts: C,
    opened_limit: VarInt,
    buffer: BufferPhase<C::Reason, F::Change>,
    connection: ConnectionPhase,
    received: ReceivedRanges,
    reset: Option<F>,
    acceptance: Boundary<C::Reason, F::Change>,
    delivery: Boundary<C::Reason, F::Change>,
    reading: Reading<C::Reason, F>,
    stop: StopRequest,
    data_complete_notified: bool,
    reset_presentation: ResetPresentation,
    released_reported: VarInt,
}

impl<C> StreamReceiver<C, RemoteReset>
where
    C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<RemoteReset>,
{
    /// Processes a `RESET_STREAM` frame of the stream.
    ///
    /// The first one establishes the reset facts. A later one changes
    /// nothing, also when it states another error code: the first code is
    /// kept. What remains deliverable is up to the receive termination
    /// policy; reading stops at the first gap. As for
    /// [`on_stream_frame`](Self::on_stream_frame), a violating frame leaves
    /// no trace, and a frame after a violation or after the connection
    /// closed is ignored.
    ///
    /// # Errors
    ///
    /// [`OnResetStreamError`] if this frame violates the protocol; the caller
    /// must close the connection with its
    /// [`transport_error_code`](OnResetStreamError::transport_error_code).
    pub fn on_reset_stream(
        &mut self,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError> {
        self.on_remote_reset(frame, connection)
            .map_err(|error| match error {
                OnRemoteResetError::Violation { source } => source,
                OnRemoteResetError::Malformed { source }
                | OnRemoteResetError::Conflict { source } => match source {},
            })
    }
}

impl<C, F> StreamReceiver<C, F>
where
    C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<F>,
    F: RemoteResetFacts,
{
    /// Creates the receive direction of a stream from its components and the
    /// stream limit the peer may already use.
    ///
    /// `initial_limit` is the initial stream limit this endpoint advertised
    /// for streams of this type in its transport parameters, combined with
    /// any later increase that already applies.
    pub fn new(parts: C, initial_limit: VarInt) -> Self {
        Self {
            parts,
            opened_limit: initial_limit,
            buffer: BufferPhase::Live,
            connection: ConnectionPhase::Open,
            received: ReceivedRanges::default(),
            reset: None,
            acceptance: Boundary::Following,
            delivery: Boundary::Following,
            reading: Reading::Open,
            stop: StopRequest::NotRequested,
            data_complete_notified: false,
            reset_presentation: ResetPresentation::default(),
            released_reported: VarInt::ZERO,
        }
    }

    /// The components.
    pub fn parts(&self) -> &C {
        &self.parts
    }

    /// The highest stream limit that may be visible to the peer.
    pub fn opened_limit(&self) -> VarInt {
        self.opened_limit
    }

    /// The reset facts, once a reset has been received.
    pub fn remote_reset(&self) -> Option<F> {
        self.reset
    }

    /// The closure of the connection, once
    /// [`connection_closed`](Self::connection_closed) recorded it.
    pub fn closed(&self) -> Option<&ConnectionClosedError> {
        match &self.connection {
            ConnectionPhase::Closed(closed) => Some(closed),
            ConnectionPhase::Open | ConnectionPhase::Violated => None,
        }
    }

    /// The data acceptance limit (`acceptance_limit`).
    pub fn acceptance_limit(&self) -> BoundaryMode {
        self.acceptance.mode()
    }

    /// The delivery limit (`delivery_limit`).
    pub fn delivery_limit(&self) -> BoundaryMode {
        self.delivery.mode()
    }

    /// Whether the stream still takes frames: no violation was returned and
    /// the connection has not closed.
    fn takes_frames(&self) -> bool {
        matches!(self.connection, ConnectionPhase::Open)
    }

    fn is_violated(&self) -> bool {
        matches!(self.connection, ConnectionPhase::Violated)
    }

    fn is_destroyed(&self) -> bool {
        !matches!(self.buffer, BufferPhase::Live)
    }

    fn is_reader_dropped(&self) -> bool {
        matches!(self.reading, Reading::ReaderDropped { .. })
    }

    fn is_result_committed(&self) -> bool {
        match self.reading {
            Reading::Open => false,
            Reading::Committed(_) => true,
            Reading::ReaderDropped { result_committed } => result_committed,
        }
    }

    /// Processes a STREAM frame of the stream.
    ///
    /// The part of the data below both local limits goes to the receive
    /// buffer; the frame's offset, end and FIN are processed in full. Every
    /// check runs before anything changes, so a frame that violates the
    /// protocol leaves no trace in the buffer, the policies or the
    /// connection's flow control.
    ///
    /// Once a frame has returned a violation, or the connection has closed,
    /// the connection is closing and the frame cannot change its outcome: this
    /// and the other frame methods then do nothing and return `Ok(())`.
    ///
    /// # Errors
    ///
    /// [`OnStreamFrameError`] if this frame violates the protocol; the caller
    /// must close the connection with its
    /// [`transport_error_code`](OnStreamFrameError::transport_error_code).
    /// The stream then exposes no new result to the application until
    /// [`connection_closed`](Self::connection_closed).
    pub fn on_stream_frame(
        &mut self,
        frame: StreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnStreamFrameError> {
        if !self.takes_frames() {
            return Ok(());
        }
        self.accept_stream_frame(frame, connection)
            .inspect_err(|_| self.connection = ConnectionPhase::Violated)
    }

    /// Processes a reset of the stream by the peer: a frame that states
    /// reset facts of type `F`.
    ///
    /// This is the entry point of every kind of reset; the methods named
    /// after a frame call it. `frame` is converted to the facts it states;
    /// the first reset establishes the facts of the stream and a later one is
    /// merged into them ([`RemoteResetFacts::merge`]). The receive
    /// termination policy observes [`TerminationEvent::RemoteReset`] or
    /// [`TerminationEvent::ResetChanged`]. Every check runs before anything
    /// changes: as for [`on_stream_frame`](Self::on_stream_frame), a
    /// violating frame leaves no trace, and a frame after a violation or
    /// after the connection closed is ignored.
    ///
    /// # Errors
    ///
    /// [`OnRemoteResetError`] if this frame violates the protocol; the caller
    /// must close the connection. The checks run in the order of the
    /// variants, except that the limits of flow control come last.
    pub fn on_remote_reset<T>(
        &mut self,
        frame: T,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnRemoteResetError<T::Error, F::Conflict>>
    where
        T: TryInto<F>,
        T::Error: Error + 'static,
    {
        if !self.takes_frames() {
            return Ok(());
        }
        self.accept_reset(frame, connection)
            .inspect_err(|_| self.connection = ConnectionPhase::Violated)
    }

    /// Processes a `STREAM_DATA_BLOCKED` frame of the stream: the receive
    /// flow control policy observes it. It grants nothing by itself.
    ///
    /// The policy does not observe it once a violation was returned or the
    /// connection has closed.
    pub fn on_stream_data_blocked(&mut self, limit: VarInt) {
        if self.takes_frames() {
            self.notify_flow(ReceiveFlowEvent::PeerBlocked { limit });
        }
    }

    /// Records that the connection closed for `reason`.
    ///
    /// The connection side calls this on every stream in the poll in which the
    /// connection records its first close reason, whichever its source, and
    /// also for a stream that returned a violation. Later operations of the
    /// application fail with [`ConnectionClosedError`], carrying `reason`. The
    /// receive buffer is destroyed. Only the first reason is kept; a later
    /// call has no effect.
    pub fn connection_closed(&mut self, reason: CloseReason) {
        if self.closed().is_some() {
            return;
        }
        self.shut_down(ConnectionClosedError::new(reason));
    }

    /// Records that the stream reader was dropped.
    ///
    /// The reader loses the only read access: the receive buffer is
    /// destroyed whatever the receive termination policy says, and the policy
    /// then observes [`TerminationEvent::ReaderDropped`]. The receive
    /// direction keeps its protocol duties — final size, flow control, a
    /// pending STOP — until the protocol lets it go. Reads after this call
    /// fail with [`ReadError::ReaderDropped`].
    pub fn reader_dropped(&mut self) {
        if self.is_reader_dropped() {
            return;
        }
        self.reading = Reading::ReaderDropped {
            result_committed: self.is_result_committed(),
        };
        self.destroy_buffer(Destruction::Forced);
        self.notify_flow(ReceiveFlowEvent::ReaderDropped);
        self.notify_termination(TerminationEvent::ReaderDropped);
    }

    /// Adds to the connection's released progress what this stream released
    /// since the last report.
    ///
    /// The stream's released progress is its accounted end less the bytes it
    /// still holds for delivery to the application: delivered data, data
    /// beyond a fixed delivery limit and everything after the buffer was
    /// destroyed count as released. Frame processing reports by itself;
    /// reads do not, since they do not see the connection. Nothing is
    /// reported after the connection closed.
    ///
    /// # Errors
    ///
    /// [`RecordReleaseError`] if `connection` has not recorded the usage this
    /// stream releases, which happens when the stream's input was accounted
    /// with another controller; nothing is reported then. Frame processing
    /// leaves such a report for the next call of this method.
    pub fn report_release(
        &mut self,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), RecordReleaseError> {
        if self.closed().is_some() {
            return Ok(());
        }
        let progress = self.release_progress();
        if let Some(increase) = progress.checked_sub(self.released_reported)
            && increase > VarInt::ZERO
        {
            connection.record_release(increase)?;
            self.released_reported = progress;
        }
        Ok(())
    }

    fn accept_stream_frame(
        &mut self,
        frame: StreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnStreamFrameError> {
        let StreamFrame { offset, data, fin } = frame;
        let Some(end) = offset_add(offset, data.len()) else {
            return OffsetOverflowSnafu {
                offset,
                len: data.len(),
            }
            .fail();
        };
        let old_accounted = self.parts.accounted_end();
        check_stream_final_size(self.parts.final_size(), old_accounted, end, fin)?;
        // The receive buffer contract: the accounted end is the maximum of
        // every end it has been given.
        let accounted_end = old_accounted.max(end);
        self.account::<OnStreamFrameError>(old_accounted, accounted_end, connection)?;
        // The frame passed every check: nothing below fails.
        let payload = self.accepted_payload(offset, data);
        let input = match StreamDataInput::new(offset, end, fin, payload) {
            Ok(input) => input,
            // invariant: the accepted payload is a prefix of the frame data,
            // which ends at `end`.
            Err(error) => unreachable!("accepted payload passes the frame: {error}"),
        };
        self.received.insert(offset, end);
        self.parts.receive_data(input);
        debug_assert_eq!(self.parts.accounted_end(), accounted_end);
        self.after_input(None, connection);
        Ok(())
    }

    fn accept_reset<T>(
        &mut self,
        frame: T,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnRemoteResetError<T::Error, F::Conflict>>
    where
        T: TryInto<F>,
        T::Error: Error + 'static,
    {
        let stated: F = frame.try_into().context(MalformedSnafu)?;
        debug_assert!(stated.owed_end() <= stated.final_size());
        let final_size = stated.final_size();
        let old_accounted = self.parts.accounted_end();
        check_reset_final_size(self.parts.final_size(), old_accounted, final_size)?;
        let update = match self.reset {
            None => Some((stated, TerminationEvent::RemoteReset)),
            Some(known) => known
                .merge(stated)
                .context(ConflictSnafu)?
                .map(|(facts, change)| {
                    debug_assert!(facts.final_size() == known.final_size());
                    debug_assert!(facts.owed_end() <= facts.final_size());
                    (facts, TerminationEvent::ResetChanged(change))
                }),
        };
        // The receive buffer contract: the accounted end is the maximum of
        // every final size it has been given.
        let accounted_end = old_accounted.max(final_size);
        self.account::<OnResetStreamError>(old_accounted, accounted_end, connection)?;
        // The frame passed every check: nothing below fails.
        self.parts.receive_final_size(final_size);
        debug_assert_eq!(self.parts.accounted_end(), accounted_end);
        let event = update.map(|(facts, event)| {
            self.reset = Some(facts);
            event
        });
        self.after_input(event, connection);
        Ok(())
    }

    /// Checks the stream limit against the accounted end a frame would reach
    /// and records the increase over `old_accounted` with the connection.
    ///
    /// The connection is charged last and only when every check passed, so a
    /// failure leaves it unchanged.
    fn account<E>(
        &self,
        old_accounted: VarInt,
        accounted_end: VarInt,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), E>
    where
        E: From<StreamLimitExceededError> + From<RecordUsageError>,
    {
        StreamLimitExceededError::check(accounted_end, self.opened_limit)?;
        connection.record_usage(accounted_end.saturating_sub(old_accounted))?;
        Ok(())
    }

    fn after_input(
        &mut self,
        event: Option<TerminationEvent<F::Change>>,
        connection: &mut ConnectionReceiveFlowController,
    ) {
        self.notify_flow(ReceiveFlowEvent::Received);
        if let Some(event) = event {
            self.notify_termination(event);
        }
        if !self.data_complete_notified && self.fully_received() {
            self.data_complete_notified = true;
            self.notify_termination(TerminationEvent::DataComplete);
        }
        // A report the connection rejects stays due; `report_release`
        // returns the error to the composing code.
        let _ = self.report_release(connection);
    }

    /// The part of `data`, which starts at `offset`, below both local limits.
    fn accepted_payload(&self, offset: VarInt, mut data: Bytes) -> Bytes {
        if self.is_destroyed() {
            return Bytes::new();
        }
        let limit = self.acceptance.limit().min(self.delivery.limit());
        data.truncate(span(offset, limit));
        data
    }

    /// Records the closure of the connection and destroys the buffer.
    fn shut_down(&mut self, closed: ConnectionClosedError) {
        self.connection = ConnectionPhase::Closed(closed);
        self.destroy_buffer(Destruction::Forced);
        self.notify_termination(TerminationEvent::ConnectionClosed);
    }

    /// Destroys the receive buffer for `cause`. A buffer already destroyed
    /// keeps its first cause.
    fn destroy_buffer(&mut self, cause: Destruction<C::Reason, F::Change>) {
        if self.is_destroyed() {
            return;
        }
        self.parts.destroy();
        self.buffer = BufferPhase::Destroyed(cause);
        self.notify_flow(ReceiveFlowEvent::BufferDestroyed);
    }

    fn fully_received(&self) -> bool {
        self.parts
            .final_size()
            .is_some_and(|final_size| self.received.covers(VarInt::ZERO..final_size))
    }

    fn stop_sent(&self) -> bool {
        matches!(self.stop, StopRequest::Sent(_))
    }

    fn release_progress(&self) -> VarInt {
        let accounted = self.parts.accounted_end();
        if self.is_destroyed() || self.is_result_committed() {
            return accounted;
        }
        let retained = self
            .delivery
            .limit()
            .min(accounted)
            .saturating_sub(self.parts.delivered_end());
        accounted.saturating_sub(retained)
    }

    fn termination_view(&self) -> TerminationView<F> {
        TerminationView {
            accounted_end: self.parts.accounted_end(),
            final_size: self.parts.final_size(),
            delivered_end: self.parts.delivered_end(),
            fully_received: self.fully_received(),
            reset: self.remote_reset(),
            acceptance: self.acceptance.mode(),
            delivery: self.delivery.mode(),
            destroyed: self.is_destroyed(),
            read_result_committed: self.is_result_committed(),
            stop_code: self.stop.code(),
            stop_sent: self.stop_sent(),
            stop_allowed: self.stop.code().is_none()
                && self.closed().is_none()
                && self.stop_not_needed().is_none(),
            reader_dropped: self.is_reader_dropped(),
            connection_closed: self.closed().is_some(),
        }
    }

    fn notify_termination(&mut self, event: TerminationEvent<F::Change>) {
        let view = self.termination_view();
        let decision = self.parts.on_termination_event(event, &view);
        self.apply_decision(event, decision);
    }

    fn notify_flow(&mut self, event: ReceiveFlowEvent) {
        let view = ReceiveFlowView {
            opened_limit: self.opened_limit,
            accounted_end: self.parts.accounted_end(),
            delivered_end: self.parts.delivered_end(),
            final_size: self.parts.final_size(),
            acceptance: self.acceptance.mode(),
            delivery: self.delivery.mode(),
            destroyed: self.is_destroyed(),
            reader_dropped: self.is_reader_dropped(),
        };
        self.parts.on_receive_flow_event(event, &view);
    }
}

fn check_stream_final_size(
    old_final: Option<VarInt>,
    old_accounted: VarInt,
    end: VarInt,
    fin: bool,
) -> Result<(), OnStreamFrameError> {
    match old_final {
        Some(final_size) => {
            if fin {
                FinalSizeChangeError::check(final_size, end)?;
            }
            BeyondFinalSizeError::check(final_size, end)?;
        }
        None if fin => FinalSizeBelowReceivedError::check(end, old_accounted)?,
        None => {}
    }
    Ok(())
}

/// Checks the final size a reset states against the known one, or else
/// against the data already received.
fn check_reset_final_size(
    old_final: Option<VarInt>,
    old_accounted: VarInt,
    final_size: VarInt,
) -> Result<(), OnResetStreamError> {
    match old_final {
        Some(known) => FinalSizeChangeError::check(known, final_size)?,
        None => FinalSizeBelowReceivedError::check(final_size, old_accounted)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests;
