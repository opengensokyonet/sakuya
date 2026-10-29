//! The stream receive component: the per-stream receive direction of a
//! connection.
//!
//! A [`StreamReceiver`] takes the frames that affect the receive direction of
//! one stream — STREAM, `RESET_STREAM`, `RESET_STREAM_AT` and
//! `STREAM_DATA_BLOCKED` — already parsed and attributed to the stream, and
//! the operations of the stream reader: reads, the local STOP request and the
//! reader being dropped. It composes three contracts that one type `C`
//! implements: the receive buffer ([`ReceiveBuffer`]), the receive flow
//! control policy ([`ReceiveFlowControlPolicy`]) and the receive termination
//! policy ([`ReceiveTerminationPolicy`]). The type may hold three independent
//! components or let the buffer double as the flow control policy; it must
//! make them work on the same stream.
//!
//! # Exclusive operations
//!
//! Every method takes `&mut self`: one operation has the whole receive
//! direction to itself, and buffer and policy calls happen inside it. A frame
//! is first handed to the receive buffer and checked afterwards: the
//! component queries the buffer's accounted end before and after, checks the
//! stream limit, and records the increase with the
//! [`ConnectionReceiveFlowController`] passed in. A failed check is kept as a
//! persistent failure without undoing what the buffer did; every later
//! operation reports it first.
//!
//! # Three independent dimensions
//!
//! - Remote end facts: the final size (kept by the buffer), the reset error
//!   code and the effective reliable size. The latter is established by the
//!   first reset, takes the smallest value any reset stated, and counts as
//!   zero for `RESET_STREAM`.
//! - Local delivery limits: the data acceptance limit (`acceptance_limit`),
//!   which bounds the new payload the buffer keeps, and the delivery limit
//!   (`delivery_limit`), which bounds delivery to the application. Each
//!   follows reception ([`BoundaryMode::Following`]) until the receive
//!   termination policy fixes it ([`BoundaryMode::Fixed`]); a fixed limit can
//!   only stay or tighten.
//! - The committed read result: once a read has returned end of stream or a
//!   terminal error, later frames do not change it.
//!
//! The reliable size is not a local truncation: it says which gaps are still
//! worth waiting for, never how far delivery may go.
//!
//! Waiting and waking, the asynchronous reader, sending `STOP_SENDING` and
//! `MAX_STREAM_DATA`, and propagating connection errors are left to the
//! surrounding composition; this module offers the synchronous entry points
//! they call. The limit actions ([`termination::BoundaryAction`]) are
//! provisional.
//!
//! [`ReceiveBuffer`]: crate::receive_buffer::ReceiveBuffer
use crate::connection_receive_flow::{
    ConnectionReceiveFlowController, RecordReleaseError, RecordUsageError,
};
use crate::receive_buffer::{ReceiveBuffer, StreamDataInput, offset_add, span};
use bytes::Bytes;
use flow_control::{ReceiveFlowControlPolicy, ReceiveFlowEvent, ReceiveFlowView};
use read::{ReadError, RemoteReset};
use sakuya_wire::application_error::ApplicationErrorCode;
use sakuya_wire::transport_error::TransportErrorCode;
use sakuya_wire::var_int::VarInt;
use snafu::{ResultExt, Snafu, ensure};
use termination::{ReceiveTerminationPolicy, ResetPresentation, TerminationEvent, TerminationView};

pub mod flow_control;
pub mod read;
pub mod stop;
pub mod termination;

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

/// A `RESET_STREAM_AT` frame of the stream
/// ([draft-ietf-quic-reliable-stream-reset-11 §4]).
///
/// The reliable stream reset extension is an Internet-Draft, not a published
/// RFC.
///
/// [draft-ietf-quic-reliable-stream-reset-11 §4]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetStreamAtFrame {
    /// The application protocol error code.
    pub code: ApplicationErrorCode,
    /// The final size of the stream.
    pub final_size: VarInt,
    /// The end of the prefix the sender still delivers reliably.
    pub reliable_size: VarInt,
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

/// A protocol violation detected on the receive direction of a stream.
///
/// Every variant is a connection error ([RFC 9000 §11]): it closes the
/// connection with the transport error code of
/// [`transport_error_code`](Self::transport_error_code). The variants keep
/// apart what was violated, so that the stream-level limit
/// ([`StreamLimitExceeded`](Self::StreamLimitExceeded)) and the
/// connection-level limit
/// ([`ConnectionLimitExceeded`](Self::ConnectionLimitExceeded)) stay
/// distinguishable although both are `FLOW_CONTROL_ERROR`.
///
/// [RFC 9000 §11]: https://www.rfc-editor.org/rfc/rfc9000.html#section-11
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum ProtocolError {
    /// A FIN or reset states a final size different from the known one
    /// (`FINAL_SIZE_ERROR`, [RFC 9000 §4.5]).
    ///
    /// [RFC 9000 §4.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5
    #[snafu(display("final size {received} differs from the known final size {final_size}"))]
    FinalSizeChanged {
        /// The known final size.
        final_size: VarInt,
        /// The final size the frame states.
        received: VarInt,
    },
    /// STREAM data ends beyond the known final size (`FINAL_SIZE_ERROR`).
    #[snafu(display("stream data ends at {end}, beyond the final size {final_size}"))]
    BeyondFinalSize {
        /// The known final size.
        final_size: VarInt,
        /// The end of the frame's data.
        end: VarInt,
    },
    /// A FIN or reset states a final size below data already received
    /// (`FINAL_SIZE_ERROR`).
    #[snafu(display("final size {final_size} is below the received end {accounted_end}"))]
    FinalSizeBelowReceived {
        /// The final size the frame states.
        final_size: VarInt,
        /// The highest end received before.
        accounted_end: VarInt,
    },
    /// The stream's accounted end exceeds the stream limit opened to the peer
    /// (`FLOW_CONTROL_ERROR`, [RFC 9000 §4.1]).
    ///
    /// [RFC 9000 §4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
    #[snafu(display("stream data reaches {accounted_end}, beyond the stream limit {limit}"))]
    StreamLimitExceeded {
        /// The accounted end after the frame.
        accounted_end: VarInt,
        /// The stream limit opened to the peer.
        limit: VarInt,
    },
    /// The connection's usage exceeds the connection limit
    /// (`FLOW_CONTROL_ERROR`).
    #[snafu(display("connection flow control violated"))]
    ConnectionLimitExceeded {
        /// The rejected usage increase.
        source: RecordUsageError,
    },
    /// A STREAM frame's offset plus length exceeds 2<sup>62</sup> − 1
    /// (`FRAME_ENCODING_ERROR`, [RFC 9000 §19.8]).
    ///
    /// [RFC 9000 §19.8]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.8
    #[snafu(display("stream data at offset {offset} with length {len} ends beyond 2^62 - 1"))]
    OffsetOverflow {
        /// The frame's offset.
        offset: VarInt,
        /// The frame's data length.
        len: usize,
    },
    /// A `RESET_STREAM_AT` states a reliable size above its final size
    /// (`FRAME_ENCODING_ERROR`, draft-ietf-quic-reliable-stream-reset-11 §4).
    #[snafu(display("reliable size {reliable_size} exceeds the final size {final_size}"))]
    ReliableSizeExceedsFinalSize {
        /// The reliable size the frame states.
        reliable_size: VarInt,
        /// The final size the frame states.
        final_size: VarInt,
    },
    /// A reset states an error code different from an earlier reset's
    /// (`STREAM_STATE_ERROR`, draft-ietf-quic-reliable-stream-reset-11 §5).
    #[snafu(display("reset error code {received} differs from the earlier code {code}"))]
    ResetCodeChanged {
        /// The error code of the earlier reset.
        code: ApplicationErrorCode,
        /// The error code the frame states.
        received: ApplicationErrorCode,
    },
}

impl ProtocolError {
    /// The QUIC transport error code to close the connection with.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::StreamLimitExceeded { .. } | Self::ConnectionLimitExceeded { .. } => {
                TransportErrorCode::FLOW_CONTROL_ERROR
            }
            Self::ResetCodeChanged { .. } => TransportErrorCode::STREAM_STATE_ERROR,
            Self::FinalSizeChanged { .. }
            | Self::BeyondFinalSize { .. }
            | Self::FinalSizeBelowReceived { .. } => TransportErrorCode::FINAL_SIZE_ERROR,
            Self::OffsetOverflow { .. } | Self::ReliableSizeExceedsFinalSize { .. } => {
                TransportErrorCode::FRAME_ENCODING_ERROR
            }
        }
    }
}

/// A failure of the connection as seen by one stream's receive direction.
///
/// It is the highest-priority result of every later operation on the
/// stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum ConnectionFailure {
    /// The connection was closed.
    #[snafu(display("connection closed"))]
    Closed,
    /// Input of this stream violated the protocol; the connection must be
    /// closed with the error's transport error code.
    #[snafu(display("protocol violation on the stream's receive direction"))]
    Protocol {
        /// The violation.
        source: ProtocolError,
    },
}

/// A local reason, and the event during which it took effect.
#[derive(Clone, Debug)]
struct Applied<R> {
    reason: R,
    trigger: TerminationEvent,
}

/// A local delivery limit with the reason it was fixed for.
#[derive(Clone, Debug)]
enum Boundary<R> {
    Following,
    Fixed { limit: VarInt, applied: Applied<R> },
}

impl<R> Boundary<R> {
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

/// The reset facts the receive direction keeps: the code and final size of
/// the first reset, and the smallest reliable size any reset stated.
#[derive(Clone, Copy, Debug)]
struct ResetFacts {
    code: ApplicationErrorCode,
    final_size: VarInt,
    reliable_size: VarInt,
}

/// What happened to the receive buffer and its payload:
///
/// ```text
///          destroy (policy, reader drop, terminal error)
///   Live ─────────────────────────────────────────────▶ Destroyed
///     │                                                     │
///     │ connection fails                   connection fails │
///     └──────────────────────────▶ Failed ◀─────────────────┘
/// ```
///
/// `Failed` is final: the connection failure is the highest-priority result
/// of every later operation, and the buffer is destroyed. A destroyed buffer
/// keeps its first cause.
#[derive(Clone, Debug)]
enum BufferPhase<R> {
    /// The buffer holds payload for delivery.
    Live,
    /// The buffer was destroyed.
    Destroyed(Destruction<R>),
    /// The connection failed; the buffer is destroyed.
    Failed(ConnectionFailure),
}

/// Why the receive buffer was destroyed.
#[derive(Clone, Debug)]
enum Destruction<R> {
    /// The receive termination policy destroyed it for this reason.
    Policy(Applied<R>),
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
enum Reading<R> {
    /// The reader may read; no result is committed.
    Open,
    /// A read committed this result; repeated reads return it.
    Committed(Committed<R>),
    /// The reader was dropped; no more reads happen.
    ReaderDropped {
        /// Whether a read had committed a result before.
        result_committed: bool,
    },
}

#[derive(Clone, Debug)]
enum Committed<R> {
    End,
    Error(ReadError<R>),
}

/// The receive direction of one stream.
///
/// `C` implements the receive buffer, the receive flow control policy and
/// the receive termination policy for this stream. See the [module
/// documentation](self) for the processing model.
#[derive(Debug)]
pub struct StreamReceiver<C: ReceiveTerminationPolicy> {
    parts: C,
    opened_limit: VarInt,
    buffer: BufferPhase<C::Reason>,
    reset: Option<ResetFacts>,
    acceptance: Boundary<C::Reason>,
    delivery: Boundary<C::Reason>,
    reading: Reading<C::Reason>,
    stop: StopRequest,
    data_complete_notified: bool,
    reset_presentation: ResetPresentation,
    released_reported: VarInt,
}

impl<C> StreamReceiver<C>
where
    C: ReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy,
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
    pub fn remote_reset(&self) -> Option<RemoteReset> {
        self.reset.map(|facts| RemoteReset {
            code: facts.code,
            final_size: facts.final_size,
            reliable_size: facts.reliable_size,
        })
    }

    /// The persistent failure, if one occurred.
    pub fn failure(&self) -> Option<ConnectionFailure> {
        match self.buffer {
            BufferPhase::Failed(failure) => Some(failure),
            BufferPhase::Live | BufferPhase::Destroyed(_) => None,
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
    /// buffer; the frame's offset, end and FIN are processed in full.
    ///
    /// # Errors
    ///
    /// Returns the persistent failure if one occurred earlier, or the new
    /// [`ConnectionFailure::Protocol`] if this frame violates the protocol;
    /// the caller must close the connection with it.
    pub fn on_stream_frame(
        &mut self,
        frame: StreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), ConnectionFailure> {
        self.check_failure()?;
        let StreamFrame { offset, data, fin } = frame;
        let Some(end) = offset_add(offset, data.len()) else {
            let error = OffsetOverflowSnafu {
                offset,
                len: data.len(),
            }
            .build();
            return Err(self.fail(error));
        };
        let old_accounted = self.parts.accounted_end();
        let old_final = self.parts.final_size();
        let payload = self.accepted_payload(offset, data);
        let input = match StreamDataInput::new(offset, end, fin, payload) {
            Ok(input) => input,
            // invariant: the accepted payload is a prefix of the frame data,
            // which ends at `end`.
            Err(error) => unreachable!("accepted payload passes the frame: {error}"),
        };
        self.parts.receive_data(input);
        let checked = check_stream_final_size(old_final, old_accounted, end, fin)
            .and_then(|()| self.account(old_accounted, connection));
        if let Err(error) = checked {
            return Err(self.fail(error));
        }
        self.after_input(None, connection);
        Ok(())
    }

    /// Processes a `RESET_STREAM` frame of the stream.
    ///
    /// It establishes the reset facts with a reliable size of zero, or lowers
    /// an earlier `RESET_STREAM_AT`'s reliable size to zero. What remains
    /// deliverable is up to the receive termination policy; reading stops at
    /// the first gap.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    pub fn on_reset_stream(
        &mut self,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), ConnectionFailure> {
        self.on_reset(frame.code, frame.final_size, VarInt::ZERO, connection)
    }

    /// Processes a `RESET_STREAM_AT` frame of the stream.
    ///
    /// The effective reliable size becomes the smallest one received; a
    /// larger one arriving later does not raise it.
    ///
    /// # Errors
    ///
    /// As [`on_stream_frame`](Self::on_stream_frame).
    pub fn on_reset_stream_at(
        &mut self,
        frame: ResetStreamAtFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), ConnectionFailure> {
        self.on_reset(
            frame.code,
            frame.final_size,
            frame.reliable_size,
            connection,
        )
    }

    /// Processes a `STREAM_DATA_BLOCKED` frame of the stream: the receive
    /// flow control policy observes it. It grants nothing by itself.
    pub fn on_stream_data_blocked(&mut self, limit: VarInt) {
        if self.failure().is_none() {
            self.notify_flow(ReceiveFlowEvent::PeerBlocked { limit });
        }
    }

    /// Records that the connection is closed.
    ///
    /// Later operations report [`ConnectionFailure::Closed`] unless a
    /// protocol failure was recorded first. The receive buffer is destroyed.
    pub fn connection_closed(&mut self) {
        if self.failure().is_some() {
            return;
        }
        self.shut_down(ConnectionFailure::Closed);
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
    /// reported after a connection failure.
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
        if self.failure().is_some() {
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

    fn on_reset(
        &mut self,
        code: ApplicationErrorCode,
        final_size: VarInt,
        reliable_size: VarInt,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), ConnectionFailure> {
        self.check_failure()?;
        if reliable_size > final_size {
            let error = ReliableSizeExceedsFinalSizeSnafu {
                reliable_size,
                final_size,
            }
            .build();
            return Err(self.fail(error));
        }
        let old_accounted = self.parts.accounted_end();
        let old_final = self.parts.final_size();
        self.parts.receive_final_size(final_size);
        let checked = self
            .check_reset(old_final, old_accounted, code, final_size)
            .and_then(|()| self.account(old_accounted, connection));
        if let Err(error) = checked {
            return Err(self.fail(error));
        }
        let event = match &mut self.reset {
            None => {
                self.reset = Some(ResetFacts {
                    code,
                    final_size,
                    reliable_size,
                });
                Some(TerminationEvent::RemoteReset)
            }
            Some(facts) if reliable_size < facts.reliable_size => {
                facts.reliable_size = reliable_size;
                Some(TerminationEvent::ReliablePrefixLowered)
            }
            Some(_) => None,
        };
        self.after_input(event, connection);
        Ok(())
    }

    fn check_reset(
        &self,
        old_final: Option<VarInt>,
        old_accounted: VarInt,
        code: ApplicationErrorCode,
        final_size: VarInt,
    ) -> Result<(), ProtocolError> {
        match old_final {
            Some(known) => ensure!(
                final_size == known,
                FinalSizeChangedSnafu {
                    final_size: known,
                    received: final_size,
                }
            ),
            None => ensure!(
                final_size >= old_accounted,
                FinalSizeBelowReceivedSnafu {
                    final_size,
                    accounted_end: old_accounted,
                }
            ),
        }
        if let Some(facts) = self.reset {
            ensure!(
                facts.code == code,
                ResetCodeChangedSnafu {
                    code: facts.code,
                    received: code,
                }
            );
        }
        Ok(())
    }

    /// Checks the stream limit and records the accounted end's increase with
    /// the connection.
    fn account(
        &self,
        old_accounted: VarInt,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), ProtocolError> {
        let accounted_end = self.parts.accounted_end();
        // The receive buffer contract keeps the accounted end from falling;
        // a buffer that breaks it records no increase.
        debug_assert!(accounted_end >= old_accounted);
        let increase = accounted_end.saturating_sub(old_accounted);
        ensure!(
            accounted_end <= self.opened_limit,
            StreamLimitExceededSnafu {
                accounted_end,
                limit: self.opened_limit,
            }
        );
        connection
            .record_usage(increase)
            .context(ConnectionLimitExceededSnafu)
    }

    fn after_input(
        &mut self,
        event: Option<TerminationEvent>,
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

    fn check_failure(&self) -> Result<(), ConnectionFailure> {
        self.failure().map_or(Ok(()), Err)
    }

    /// Records a protocol violation as the persistent failure.
    fn fail(&mut self, error: ProtocolError) -> ConnectionFailure {
        let failure = ConnectionFailure::Protocol { source: error };
        self.shut_down(failure);
        failure
    }

    /// Records `failure` as the persistent failure and destroys the buffer.
    fn shut_down(&mut self, failure: ConnectionFailure) {
        let was_live = !self.is_destroyed();
        self.buffer = BufferPhase::Failed(failure);
        if was_live {
            self.parts.destroy();
            self.notify_flow(ReceiveFlowEvent::BufferDestroyed);
        }
        self.notify_termination(TerminationEvent::ConnectionClosed);
    }

    /// Destroys the receive buffer for `cause`. A buffer already destroyed
    /// keeps its first cause.
    fn destroy_buffer(&mut self, cause: Destruction<C::Reason>) {
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
            .is_some_and(|final_size| self.parts.is_received(VarInt::ZERO..final_size))
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

    fn termination_view(&self) -> TerminationView {
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
                && self.failure().is_none()
                && self.stop_not_needed().is_none(),
            reader_dropped: self.is_reader_dropped(),
            connection_failed: self.failure().is_some(),
        }
    }

    fn notify_termination(&mut self, event: TerminationEvent) {
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
) -> Result<(), ProtocolError> {
    match old_final {
        Some(final_size) => {
            ensure!(
                !fin || end == final_size,
                FinalSizeChangedSnafu {
                    final_size,
                    received: end,
                }
            );
            ensure!(end <= final_size, BeyondFinalSizeSnafu { final_size, end });
        }
        None => ensure!(
            !fin || end >= old_accounted,
            FinalSizeBelowReceivedSnafu {
                final_size: end,
                accounted_end: old_accounted,
            }
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
