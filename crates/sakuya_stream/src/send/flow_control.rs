//! The stream send flow-control policy ([`SendFlowControlPolicy`]): write
//! admission and the `STREAM_DATA_BLOCKED` signal intent of one stream.
//!
//! One policy instance makes both decisions because they need the same
//! observations: the offset of a write attempt, its demand, the peer's stream
//! limit, the write limit end, a snapshot of the available connection credit
//! and what happened to earlier admissions.
//!
//! Admission is granted per write attempt as an [`AdmissionGuard`]. The guard
//! does not borrow the policy, so the stream sender can append to the send
//! buffer while the guard is outstanding; it hands the guard back with the
//! amount actually used, or as abandoned when no connection credit could be
//! reserved. A grant never carries over to a later attempt.
//!
//! The signal intent is the policy's own state: events update it and the send
//! mechanism queries it at a sending opportunity
//! ([`SendFlowControlPolicy::wants_stream_data_blocked`]). The frame's limit
//! is always the current peer stream limit.
use super::local_reset::{LocalReset, LocalResetTarget};
use super::{EndSource, SendEndState, SendTerminalState};
use sakuya_wire::v1::stream_id::StreamId;
use sakuya_wire::var_int::VarInt;
use snafu::{ResultExt, Snafu, ensure};

/// The stream send flow-control policy (`SendFlowControlPolicy`).
///
/// The policy chooses how admission and signalling are used; it cannot
/// change limits or the ledgers of the stream or the connection.
///
/// # Contract
///
/// A guard returned from [`admit_write`](Self::admit_write) must have been
/// built from the attempt passed in, so that it grants at most that
/// attempt's ceiling at that attempt's offset. The stream sender checks this
/// before it consumes any input and panics on a guard that violates it: that
/// is a defect of the policy, not an error of the write.
pub trait SendFlowControlPolicy<T: LocalResetTarget = LocalReset> {
    /// Decides the admission of one write attempt.
    ///
    /// Returns a guard for at most [`WriteAttempt::ceiling`] bytes, or `None`
    /// to admit nothing this time. The policy is consulted also when the
    /// ceiling is zero because the stream limit is exhausted, so that it
    /// learns of the blockage; it must return `None` then.
    ///
    /// A grant is an upper bound: the connection credit actually reserved may
    /// be smaller, which is no violation.
    fn admit_write(
        &mut self,
        attempt: &WriteAttempt,
        context: &SendFlowContext<T>,
    ) -> Option<AdmissionGuard>;

    /// Takes back a guard whose attempt appended `used` bytes, with
    /// `0 < used <= guard.granted()`, at `guard.offset()`.
    ///
    /// The appended range is `guard.offset()..guard.offset() + used`; no
    /// separate append event follows.
    fn on_admission_used(
        &mut self,
        guard: AdmissionGuard,
        used: VarInt,
        context: &SendFlowContext<T>,
    );

    /// Takes back a guard whose attempt appended nothing because no
    /// connection credit was available.
    fn on_admission_abandoned(&mut self, guard: AdmissionGuard, context: &SendFlowContext<T>);

    /// Observes an event; the policy may update its signal intent.
    ///
    /// Events cannot produce admission for a later attempt.
    fn on_flow_event(&mut self, event: StreamCreditEvent, context: &SendFlowContext<T>);

    /// Whether a `STREAM_DATA_BLOCKED` frame should be sent now.
    ///
    /// Querying neither consumes the intent nor counts as sending.
    fn wants_stream_data_blocked(&self, context: &SendFlowContext<T>) -> bool;
}

/// The admission granted to one write attempt.
///
/// Neither clonable nor reusable: the stream sender hands it back to the
/// policy exactly once, with the amount used or as abandoned. It owns no
/// connection credit; that is reserved separately afterwards.
#[derive(Debug, PartialEq, Eq)]
pub struct AdmissionGuard {
    offset: VarInt,
    granted: VarInt,
}

impl AdmissionGuard {
    /// Grants `granted` bytes to `attempt`.
    ///
    /// # Errors
    ///
    /// [`AdmissionGrantError::Zero`] if `granted` is zero, then
    /// [`AdmissionGrantError::AboveCeiling`] if it exceeds
    /// `attempt.ceiling`.
    pub fn new(attempt: &WriteAttempt, granted: VarInt) -> Result<Self, AdmissionGrantError> {
        ensure!(granted > VarInt::ZERO, admission_grant_error::ZeroSnafu);
        GrantAboveCeilingError::check(granted, attempt.ceiling)
            .context(admission_grant_error::AboveCeilingSnafu)?;
        Ok(Self {
            offset: attempt.offset,
            granted,
        })
    }

    /// The offset the attempt appends at.
    pub fn offset(&self) -> VarInt {
        self.offset
    }

    /// The most the attempt may append.
    pub fn granted(&self) -> VarInt {
        self.granted
    }
}

/// [`AdmissionGuard::new`] was asked for a grant outside `1..=ceiling`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(admission_grant_error), visibility(pub(crate)))]
pub enum AdmissionGrantError {
    /// The grant is zero; a policy that admits nothing returns `None`
    /// instead of granting zero bytes.
    #[snafu(display("a grant of zero bytes is no admission"))]
    Zero,
    /// The grant exceeds the attempt's ceiling.
    #[snafu(display("the grant exceeds the attempt's ceiling"))]
    AboveCeiling {
        /// The rejected grant and the ceiling.
        source: GrantAboveCeilingError,
    },
}

/// A grant exceeds the ceiling of the attempt it was made for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("a grant of {granted} bytes exceeds the ceiling {ceiling}"))]
pub struct GrantAboveCeilingError {
    granted: VarInt,
    ceiling: VarInt,
}

impl GrantAboveCeilingError {
    /// Checks that `granted` does not exceed `ceiling`.
    ///
    /// # Errors
    ///
    /// [`GrantAboveCeilingError`] if `granted` exceeds `ceiling`.
    pub(crate) fn check(granted: VarInt, ceiling: VarInt) -> Result<(), Self> {
        ensure!(
            granted <= ceiling,
            GrantAboveCeilingSnafu { granted, ceiling }
        );
        Ok(())
    }

    /// The rejected grant, which exceeds [`ceiling`](Self::ceiling).
    pub const fn granted(self) -> VarInt {
        self.granted
    }

    /// The attempt's ceiling.
    pub const fn ceiling(self) -> VarInt {
        self.ceiling
    }
}

/// One write attempt, as presented to [`SendFlowControlPolicy::admit_write`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteAttempt {
    /// The offset the attempt appends at: the current written end.
    pub offset: VarInt,
    /// The bytes the caller's input offers, saturated at [`VarInt::MAX`].
    pub requested: VarInt,
    /// The room below the peer's stream limit.
    pub stream_available: VarInt,
    /// The room below the write limit end, if one is set.
    pub write_limit_remaining: Option<VarInt>,
    /// A snapshot of the available connection credit.
    pub connection_available: VarInt,
    /// The most a grant may cover: the smallest of `requested`,
    /// `stream_available` and `write_limit_remaining`, and never past
    /// [`VarInt::MAX`]. Connection credit is not part of it; it bounds the
    /// reservation instead.
    pub ceiling: VarInt,
}

impl WriteAttempt {
    /// Whether the peer's stream limit, rather than the input or the write
    /// limit, is what keeps the attempt from taking its whole input.
    pub fn is_stream_limited(&self) -> bool {
        let wanted = self
            .write_limit_remaining
            .map_or(self.requested, |remaining| remaining.min(self.requested));
        self.stream_available < wanted
    }
}

/// The stream facts a flow-control policy reads when deciding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SendFlowContext<T: LocalResetTarget = LocalReset> {
    /// The stream's ID.
    pub stream_id: StreamId,
    /// The written end.
    pub written_end: VarInt,
    /// The exposure end.
    pub exposure_end: VarInt,
    /// The peer's stream limit in effect.
    pub peer_stream_limit: VarInt,
    /// The write limit end, if set.
    pub write_limit_end: Option<VarInt>,
    /// The end state.
    pub end_state: SendEndState<T>,
    /// The terminal state, once reached.
    pub terminal_state: Option<SendTerminalState>,
}

/// Events of one stream that a flow-control policy observes
/// (`StreamCreditEvent`).
///
/// Each describes a change already in effect; the context passed along shows
/// the state after it. Appends are not repeated as events: the guard's
/// settlement reports them. The set of events is provisional and may grow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamCreditEvent {
    /// The exposure end grew.
    FirstExposed {
        /// The new exposure end.
        exposure_end: VarInt,
    },
    /// The peer's stream limit grew.
    PeerStreamLimitIncreased {
        /// The limit before.
        previous_limit: VarInt,
        /// The limit now.
        current_limit: VarInt,
    },
    /// A `STREAM_DATA_BLOCKED` frame was sent.
    StreamBlockedSignalSent {
        /// The limit the frame carried.
        stream_data_limit: VarInt,
    },
    /// A `STREAM_DATA_BLOCKED` frame was acknowledged.
    StreamBlockedSignalAcknowledged {
        /// The limit the acknowledged frame carried.
        stream_data_limit: VarInt,
    },
    /// The write limit end narrowed.
    WriteLimitNarrowed {
        /// The new write limit end.
        write_limit_end: VarInt,
    },
    /// A close or reset was committed.
    EndCommitted {
        /// Who committed it.
        source: EndSource,
    },
}

/// A flow-control policy that admits the whole ceiling of each attempt.
///
/// - Admits all the room the attempt's hard constraints leave; it does not
///   balance streams against each other.
/// - Wants `STREAM_DATA_BLOCKED` only when an attempt is actually limited by
///   the peer's stream limit. Once a frame carrying the current limit is sent
///   it does not want another for that limit; a growth of the limit clears
///   the intent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FullCeilingAdmission {
    wants_signal: bool,
    signalled_limit: Option<VarInt>,
}

/// The flow-control policy of the default composition.
pub type DefaultSendFlowControlPolicy = FullCeilingAdmission;

impl FullCeilingAdmission {
    /// Creates the policy with no signal intent.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T: LocalResetTarget> SendFlowControlPolicy<T> for FullCeilingAdmission {
    fn admit_write(
        &mut self,
        attempt: &WriteAttempt,
        context: &SendFlowContext<T>,
    ) -> Option<AdmissionGuard> {
        if attempt.is_stream_limited() && self.signalled_limit != Some(context.peer_stream_limit) {
            self.wants_signal = true;
        }
        AdmissionGuard::new(attempt, attempt.ceiling).ok()
    }

    fn on_admission_used(&mut self, _: AdmissionGuard, _: VarInt, _: &SendFlowContext<T>) {}

    fn on_admission_abandoned(&mut self, _: AdmissionGuard, _: &SendFlowContext<T>) {}

    fn on_flow_event(&mut self, event: StreamCreditEvent, context: &SendFlowContext<T>) {
        match event {
            StreamCreditEvent::PeerStreamLimitIncreased { .. } => self.wants_signal = false,
            StreamCreditEvent::StreamBlockedSignalSent { stream_data_limit } => {
                self.signalled_limit = Some(stream_data_limit);
                if stream_data_limit == context.peer_stream_limit {
                    self.wants_signal = false;
                }
            }
            _ => {}
        }
    }

    fn wants_stream_data_blocked(&self, _: &SendFlowContext<T>) -> bool {
        self.wants_signal
    }
}
